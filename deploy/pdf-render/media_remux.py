"""A video made sendable without re-encoding it: `POST /media/remux` (see app.py).

Screen and browser recorders save MP4 files in fragments: a `moov` box whose sample tables list no
samples (plus an `mvex` box), then `moof` + `mdat` pairs that carry every frame. Players read those
fine, but WhatsApp (Meta) reads only the `moov` sample tables, finds no samples and fails the
message with 131053 "No video stream found". Copying the streams into a new MP4 (`ffmpeg -c copy
-movflags +faststart`) writes one `moov` that lists every sample, in front of one `mdat`: the same
picture and sound, bit for bit, in the form every reader takes.

`transcode=True` (optional) also re-encodes a video that is not H.264 (or sound that is not AAC)
into H.264 / AAC, the codecs WhatsApp takes. That costs real CPU time, so it is only done when the
caller asks for it; a plain remux never re-encodes.
"""

import json
import os
import struct
import subprocess
import tempfile

FFMPEG = os.environ.get("FFMPEG", "ffmpeg")
FFPROBE = os.environ.get("FFPROBE", "ffprobe")
WHATSAPP_VIDEO = {"h264"}
WHATSAPP_AUDIO = {"aac"}


class BadMedia(Exception):
    """The input is not a video ffmpeg can read, or has no video stream."""


class Busy(Exception):
    """ffmpeg did not finish in time."""


def boxes(data, start=0, end=None):
    """The ISO BMFF boxes from `start` to `end`: (type, offset of the payload, end of the box)."""
    end = len(data) if end is None else end
    i = start
    while i + 8 <= end:
        size, kind = struct.unpack(">I4s", data[i:i + 8])
        head = 8
        if size == 1:
            if i + 16 > end:
                return
            size = struct.unpack(">Q", data[i + 8:i + 16])[0]
            head = 16
        elif size == 0:
            size = end - i
        if size < head or i + size > end:
            return
        yield kind.decode("latin-1"), i + head, i + size
        i += size


def is_mp4(data):
    return len(data) >= 8 and data[4:8] == b"ftyp"


def is_fragmented(data):
    """True for a fragmented MP4: a `moof` box at the top, or an `mvex` box in the `moov`."""
    if not is_mp4(data):
        return False
    for kind, body, end in boxes(data):
        if kind == "moof":
            return True
        if kind == "moov" and any(k == "mvex" for k, _, _ in boxes(data, body, end)):
            return True
    return False


def _run(args, timeout):
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Busy(f"{os.path.basename(args[0])} took longer than {timeout:.0f} s") from None


def probe(path, timeout=30):
    """ffprobe's streams and format of `path`."""
    r = _run([FFPROBE, "-v", "error", "-print_format", "json", "-show_streams", "-show_format", path], timeout)
    if r.returncode:
        why = r.stderr.decode(errors="replace").replace(path + ": ", "").strip()
        raise BadMedia("not a video file ffprobe can read: " + why[:200])
    return json.loads(r.stdout or b"{}")


def _first(streams, kind):
    return next((s for s in streams if s.get("codec_type") == kind), None)


def remux(data, transcode=False, timeout=120.0):
    """`data` (a video file) rewritten as a plain MP4 with its streams copied: `(bytes, result)`.
    `result` says what was done: {fragmented, video, audio, transcoded, frames, bytesIn, bytesOut}."""
    if not data:
        raise BadMedia("empty body")
    fragmented = is_fragmented(data)
    with tempfile.TemporaryDirectory(prefix="remux-") as tmp:
        src, out = os.path.join(tmp, "in"), os.path.join(tmp, "out.mp4")
        with open(src, "wb") as f:
            f.write(data)
        streams = probe(src).get("streams") or []
        video, audio = _first(streams, "video"), _first(streams, "audio")
        if video is None:
            raise BadMedia("no video stream in the file")
        vcodec, acodec = video.get("codec_name"), (audio or {}).get("codec_name")
        recode_video = transcode and vcodec not in WHATSAPP_VIDEO
        recode_audio = transcode and audio is not None and acodec not in WHATSAPP_AUDIO
        args = [FFMPEG, "-nostdin", "-v", "error", "-y", "-i", src, "-map", "0:v:0", "-map", "0:a:0?", "-dn", "-sn"]
        args += ["-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p", "-profile:v", "main"] if recode_video else ["-c:v", "copy"]
        args += ["-c:a", "aac", "-b:a", "128k"] if recode_audio else ["-c:a", "copy"]
        args += ["-movflags", "+faststart", "-f", "mp4", out]
        r = _run(args, timeout)
        if r.returncode or not os.path.exists(out):
            raise BadMedia("ffmpeg could not rewrite the file: " + r.stderr.decode(errors="replace").strip()[:300])
        with open(out, "rb") as f:
            result_bytes = f.read()
        # what a reader of the moov alone (WhatsApp) sees: the frames its sample tables list
        check = _first(probe(out).get("streams") or [], "video") or {}
        frames = int(check.get("nb_frames") or 0)
        if is_fragmented(result_bytes) or frames <= 0:
            raise BadMedia("the rewritten file still lists no video samples")
    return result_bytes, {
        "fragmented": fragmented,
        "video": "h264" if recode_video else vcodec,
        "audio": ("aac" if recode_audio else acodec) if audio is not None else None,
        "transcoded": bool(recode_video or recode_audio),
        "frames": frames,
        "bytesIn": len(data),
        "bytesOut": len(result_bytes),
    }

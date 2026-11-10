"""media_remux and `POST /media/remux`: a fragmented MP4 (as screen recorders save) comes back as a
plain MP4 whose moov lists every frame, streams copied; a plain MP4 is not fragmented; a body that is
not a video is refused with 400. Skipped where ffmpeg is not installed.

    python -m unittest test_media
"""
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import app
import media_remux

HAVE_FFMPEG = shutil.which(media_remux.FFMPEG) and shutil.which(media_remux.FFPROBE)


def _video(path, *extra, codec="libx264"):
    """A 2 second test picture (and tone) written with `extra` output options."""
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25:duration=2",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=2", "-c:v", codec, "-pix_fmt", "yuv420p", "-c:a", "aac",
                    "-shortest", *extra, path], check=True)
    with open(path, "rb") as f:
        return f.read()


@unittest.skipUnless(HAVE_FFMPEG, "ffmpeg is not installed")
class RemuxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = cls.dir.name
        cls.fragmented = _video(os.path.join(d, "frag.mp4"), "-movflags", "frag_keyframe+empty_moov")
        cls.plain = _video(os.path.join(d, "plain.mp4"))
        cls.mpeg4 = _video(os.path.join(d, "mpeg4.mp4"), "-movflags", "frag_keyframe+empty_moov", codec="mpeg4")

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_detects_fragments(self):
        self.assertTrue(media_remux.is_fragmented(self.fragmented))
        self.assertFalse(media_remux.is_fragmented(self.plain))
        self.assertFalse(media_remux.is_fragmented(b"%PDF-1.7 not a video"))

    def test_fragmented_becomes_plain_with_streams_copied(self):
        out, result = media_remux.remux(self.fragmented)
        self.assertFalse(media_remux.is_fragmented(out))
        self.assertTrue(result["fragmented"])
        self.assertFalse(result["transcoded"])
        self.assertEqual((result["video"], result["audio"]), ("h264", "aac"))
        self.assertEqual(result["frames"], 50)
        # +faststart: the moov comes before the mdat
        kinds = [k for k, _, _ in media_remux.boxes(out)]
        self.assertLess(kinds.index("moov"), kinds.index("mdat"))

    def test_transcode_only_when_asked(self):
        _, kept = media_remux.remux(self.mpeg4)
        self.assertEqual((kept["video"], kept["transcoded"]), ("mpeg4", False))
        out, done = media_remux.remux(self.mpeg4, transcode=True)
        self.assertEqual((done["video"], done["transcoded"]), ("h264", True))
        self.assertFalse(media_remux.is_fragmented(out))

    def test_not_a_video(self):
        with self.assertRaises(media_remux.BadMedia):
            media_remux.remux(b"hello, this is text")
        with self.assertRaises(media_remux.BadMedia):
            media_remux.remux(b"")

    def test_http_route(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            req = urllib.request.Request(base + "/media/remux", data=self.fragmented, headers={"Content-Type": "video/mp4"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                self.assertEqual(resp.headers.get_content_type(), "video/mp4")
                result = json.loads(resp.headers["X-Result"])
                body = resp.read()
            self.assertTrue(result["fragmented"])
            self.assertFalse(media_remux.is_fragmented(body))
            bad = urllib.request.Request(base + "/media/remux", data=b"not a video", headers={"Content-Type": "video/mp4"})
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(bad, timeout=30)
            self.assertEqual(e.exception.code, 400)
            e.exception.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

//! `applyOptionsMakeResource`: resize, crop and pad an image for a download.
//!
//! Geometry is the Java service's exactly: the same target sizes, crop offsets and padding
//! positions, so a layout built against one renders the same against the other. Pixels are not
//! bit-identical, because the resampler is different (Lanczos3 here, imgscalr's ULTRA_QUALITY
//! there), and the encoders differ.
//!
//! On any failure the Java service answers 200 with an empty body; so does this.
//! One difference: `format=webp` produces a WebP here. Java has no WebP writer, so it sends an
//! empty body for it. `avif` is empty in both.

use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::codecs::webp::WebPEncoder;
use image::imageops::{self, FilterType};
use image::{DynamicImage, ImageEncoder, Rgba, RgbaImage, RgbImage};

use crate::options::{DownloadOptions, Fit, Format, Gravity};

/// `imageType`: the explicit format, else the file's extension if it names one, else jpeg.
fn target_format(file_name: &str, format: Format) -> Format {
    if format != Format::General && format != Format::Auto {
        return format;
    }
    let Some(i) = file_name.rfind('.') else { return Format::Jpeg };
    Format::parse(&file_name[i + 1..].to_ascii_lowercase()).unwrap_or(Format::Jpeg)
}

fn is_jpeg(f: Format) -> bool {
    matches!(f, Format::Jpeg | Format::Jpg)
}

/// The transformed bytes, or empty when the image cannot be read or written.
pub fn transform(options: &DownloadOptions, file_name: &str, bytes: &[u8]) -> Vec<u8> {
    match try_transform(options, file_name, bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, file_name, "image resize issue");
            Vec::new()
        }
    }
}

fn try_transform(options: &DownloadOptions, file_name: &str, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let target = target_format(file_name, options.format());
    let original = image::load_from_memory(bytes)?;
    let w = options.width.map(|v| v.max(1) as u32).unwrap_or(original.width());
    let h = options.height.map(|v| v.max(1) as u32).unwrap_or(original.height());

    let processed: DynamicImage = match options.fit {
        Fit::ScaleDown => scale_down(&original, w, h),
        Fit::Contain => contain(&original, w, h, options.gravity, options.background.as_deref(), target),
        Fit::Cover => cover(&original, w, h, options.gravity),
        Fit::Crop => crop(&original, w, h, options.gravity),
        Fit::Pad => contain(
            &original,
            w,
            h,
            options.gravity,
            Some(options.background.as_deref().unwrap_or("#FFFFFF")),
            target,
        ),
    };

    encode(processed, target)
}

fn resize(src: &DynamicImage, w: u32, h: u32) -> DynamicImage {
    src.resize_exact(w.max(1), h.max(1), FilterType::Lanczos3)
}

/// Shrinks only when larger than the box, keeping the aspect ratio.
fn scale_down(src: &DynamicImage, tw: u32, th: u32) -> DynamicImage {
    let (sw, sh) = (src.width(), src.height());
    if sw > tw || sh > th {
        let ro = sw as f64 / sh as f64;
        let rt = tw as f64 / th as f64;
        let (nw, nh) = if ro > rt {
            (tw, (tw as f64 / ro) as u32)
        } else {
            ((th as f64 * ro) as u32, th)
        };
        return resize(src, nw, nh);
    }
    src.clone()
}

/// Fits inside the box; pads to the box when a background is given.
fn contain(
    src: &DynamicImage,
    tw: u32,
    th: u32,
    gravity: Gravity,
    background: Option<&str>,
    target: Format,
) -> DynamicImage {
    let ro = src.width() as f64 / src.height() as f64;
    let rt = tw as f64 / th as f64;
    let (nw, nh) = if ro > rt {
        (tw, (tw as f64 / ro) as u32)
    } else {
        ((th as f64 * ro) as u32, th)
    };
    let scaled = resize(src, nw, nh);
    match background {
        None => scaled,
        Some(bg) => pad(&scaled, tw, th, gravity, bg, target),
    }
}

/// Fills the box, then crops the overflow by gravity.
fn cover(src: &DynamicImage, tw: u32, th: u32, gravity: Gravity) -> DynamicImage {
    let ro = src.width() as f64 / src.height() as f64;
    let rt = tw as f64 / th as f64;
    let (sw, sh) = if ro > rt {
        ((th as f64 * ro) as u32, th)
    } else {
        (tw, (tw as f64 / ro) as u32)
    };
    let scaled = resize(src, sw, sh);
    crop(&scaled, tw, th, gravity)
}

fn crop(src: &DynamicImage, tw: u32, th: u32, gravity: Gravity) -> DynamicImage {
    let (sw, sh) = (src.width(), src.height());
    let w = tw.min(sw);
    let h = th.min(sh);
    let (x, y) = match gravity {
        Gravity::Top => ((sw - w) / 2, 0),
        Gravity::Bottom => ((sw - w) / 2, sh - h),
        Gravity::Left => (0, (sh - h) / 2),
        Gravity::Right => (sw - w, (sh - h) / 2),
        Gravity::Auto => ((sw - w) / 2, (sh - h) / 2),
    };
    src.crop_imm(x, y, w, h)
}

/// The image placed on a `tw` x `th` canvas by gravity. Offsets can be negative when the image is
/// larger than the canvas; the overflow is clipped, as `Graphics2D.drawImage` clips it.
fn pad(src: &DynamicImage, tw: u32, th: u32, gravity: Gravity, bg: &str, target: Format) -> DynamicImage {
    let fill = parse_color_or_white(Some(bg), target);
    let mut canvas = RgbaImage::from_pixel(tw.max(1), th.max(1), fill.unwrap_or(Rgba([0, 0, 0, 0])));
    let dw = tw as i64 - src.width() as i64;
    let dh = th as i64 - src.height() as i64;
    let (x, y) = match gravity {
        Gravity::Top => (dw / 2, 0),
        Gravity::Bottom => (dw / 2, dh),
        Gravity::Left => (0, dh / 2),
        Gravity::Right => (dw, dh / 2),
        Gravity::Auto => (dw / 2, dh / 2),
    };
    imageops::overlay(&mut canvas, &src.to_rgba8(), x, y);
    if is_jpeg(target) {
        DynamicImage::ImageRgb8(DynamicImage::ImageRgba8(canvas).to_rgb8())
    } else {
        DynamicImage::ImageRgba8(canvas)
    }
}

/// `parseColorOrWhite`: no background means white for jpeg and transparent otherwise; an
/// unreadable one means white.
fn parse_color_or_white(bg: Option<&str>, target: Format) -> Option<Rgba<u8>> {
    let white = Rgba([255, 255, 255, 255]);
    match bg {
        None => is_jpeg(target).then_some(white),
        Some(s) => Some(java_color_decode(s).unwrap_or(white)),
    }
}

/// `java.awt.Color.decode`, which is `Integer.decode`: `#`/`0x` hex, a leading `0` octal, else
/// decimal. So `#FFF` is 0x000FFF, a blue, not white.
fn java_color_decode(s: &str) -> Option<Rgba<u8>> {
    let s = s.trim();
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let value = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")).or_else(|| body.strip_prefix('#')) {
        i64::from_str_radix(h, 16).ok()?
    } else if body.len() > 1 && body.starts_with('0') {
        i64::from_str_radix(&body[1..], 8).ok()?
    } else {
        body.parse::<i64>().ok()?
    };
    let v = if neg { -value } else { value };
    let v = i32::try_from(v).ok()? as u32;
    Some(Rgba([(v >> 16) as u8, (v >> 8) as u8, v as u8, 255]))
}

fn encode(img: DynamicImage, target: Format) -> anyhow::Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::new());
    match target {
        Format::Png => {
            let rgba = img.to_rgba8();
            PngEncoder::new(&mut out).write_image(
                rgba.as_raw(),
                rgba.width(),
                rgba.height(),
                image::ExtendedColorType::Rgba8,
            )?;
        }
        Format::Jpeg | Format::Jpg => {
            // An image with alpha drawn onto an RGB canvas lands on black, as in Java.
            let rgb = flatten_on_black(&img);
            JpegEncoder::new_with_quality(&mut out, 75).write_image(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ExtendedColorType::Rgb8,
            )?;
        }
        Format::Webp => {
            let rgba = img.to_rgba8();
            WebPEncoder::new_lossless(&mut out).write_image(
                rgba.as_raw(),
                rgba.width(),
                rgba.height(),
                image::ExtendedColorType::Rgba8,
            )?;
        }
        Format::Avif | Format::General | Format::Auto => {
            anyhow::bail!("no writer for {target:?}");
        }
    }
    Ok(out.into_inner())
}

fn flatten_on_black(img: &DynamicImage) -> RgbImage {
    let rgba = img.to_rgba8();
    let mut rgb = RgbImage::new(rgba.width(), rgba.height());
    for (x, y, p) in rgba.enumerate_pixels() {
        let a = p[3] as u32;
        rgb.put_pixel(
            x,
            y,
            image::Rgb([
                (p[0] as u32 * a / 255) as u8,
                (p[1] as u32 * a / 255) as u8,
                (p[2] as u32 * a / 255) as u8,
            ]),
        );
    }
    rgb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = DynamicImage::ImageRgba8(RgbaImage::from_pixel(w, h, Rgba([200, 10, 10, 255])));
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn opts(pairs: &[(&str, &str)]) -> DownloadOptions {
        let q: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DownloadOptions::from_query(&q).unwrap()
    }

    fn dims(bytes: &[u8]) -> (u32, u32) {
        let i = image::load_from_memory(bytes).unwrap();
        (i.width(), i.height())
    }

    #[test]
    fn geometry_matches_java() {
        let src = png(400, 200);
        assert_eq!(dims(&transform(&opts(&[("width", "100")]), "a.png", &src)), (100, 50));
        assert_eq!(dims(&transform(&opts(&[("width", "100"), ("height", "100")]), "a.png", &src)), (100, 50));
        assert_eq!(
            dims(&transform(&opts(&[("width", "100"), ("height", "100"), ("fit", "pad")]), "a.png", &src)),
            (100, 100)
        );
        assert_eq!(
            dims(&transform(&opts(&[("width", "100"), ("height", "100"), ("fit", "cover")]), "a.png", &src)),
            (100, 100)
        );
        assert_eq!(
            dims(&transform(&opts(&[("width", "1000"), ("height", "1000"), ("fit", "scale_down")]), "a.png", &src)),
            (400, 200)
        );
        assert_eq!(
            dims(&transform(&opts(&[("width", "50"), ("height", "500"), ("fit", "crop")]), "a.png", &src)),
            (50, 200)
        );
    }

    #[test]
    fn formats() {
        let src = png(40, 20);
        let jpeg = transform(&opts(&[("width", "10"), ("format", "jpeg")]), "a.png", &src);
        assert_eq!(image::guess_format(&jpeg).unwrap(), image::ImageFormat::Jpeg);
        let webp = transform(&opts(&[("width", "10"), ("format", "webp")]), "a.png", &src);
        assert_eq!(image::guess_format(&webp).unwrap(), image::ImageFormat::WebP);
        assert!(transform(&opts(&[("format", "avif")]), "a.png", &src).is_empty());
        assert!(transform(&opts(&[("width", "10")]), "a.png", b"not an image").is_empty());
    }

    #[test]
    fn java_color_decode_quirks() {
        assert_eq!(java_color_decode("#FFFFFF"), Some(Rgba([255, 255, 255, 255])));
        assert_eq!(java_color_decode("#FFF"), Some(Rgba([0, 15, 255, 255])));
        assert_eq!(java_color_decode("0x00FF00"), Some(Rgba([0, 255, 0, 255])));
        assert_eq!(java_color_decode("red"), None);
    }


    #[test]
    fn every_fit_and_gravity() {
        let wide = png(400, 200);
        let tall = png(200, 400);
        let d = |pairs: &[(&str, &str)], src: &[u8]| dims(&transform(&opts(pairs), "a.png", src));
        // scale_down shrinks into the box, by width or by height.
        assert_eq!(d(&[("width", "100"), ("height", "100"), ("fit", "scale_down")], &wide), (100, 50));
        assert_eq!(d(&[("width", "300"), ("height", "40"), ("fit", "scale_down")], &wide), (80, 40));
        // cover of a tall image fills the width, then crops.
        assert_eq!(d(&[("width", "100"), ("height", "100"), ("fit", "cover")], &tall), (100, 100));
        for g in ["top", "bottom", "left", "right", "auto"] {
            assert_eq!(d(&[("width", "50"), ("height", "50"), ("fit", "crop"), ("gravity", g)], &wide), (50, 50), "{g}");
            assert_eq!(d(&[("width", "100"), ("height", "100"), ("fit", "pad"), ("gravity", g)], &wide), (100, 100), "{g}");
        }
        // contain with a background pads; a JPEG pad has no alpha.
        assert_eq!(d(&[("width", "100"), ("height", "100"), ("background", "#000000")], &wide), (100, 100));
        let jpeg = transform(&opts(&[("width", "60"), ("height", "60"), ("fit", "pad"), ("format", "jpg")]), "a.png", &wide);
        assert_eq!(image::guess_format(&jpeg).unwrap(), image::ImageFormat::Jpeg);
        // Without an explicit format the name decides; an unknown extension is JPEG.
        let named = transform(&opts(&[("width", "10")]), "a.webp", &wide);
        assert_eq!(image::guess_format(&named).unwrap(), image::ImageFormat::WebP);
        let unknown = transform(&opts(&[("width", "10")]), "a.bin", &wide);
        assert_eq!(image::guess_format(&unknown).unwrap(), image::ImageFormat::Jpeg);
        let none = transform(&opts(&[("width", "10"), ("format", "auto")]), "noext", &wide);
        assert_eq!(image::guess_format(&none).unwrap(), image::ImageFormat::Jpeg);
        assert_eq!(dims(&transform(&opts(&[("width", "-5")]), "a.png", &wide)), (1, 1));
    }

    #[test]
    fn colors_and_encoders() {
        assert_eq!(parse_color_or_white(None, Format::Jpeg), Some(Rgba([255, 255, 255, 255])));
        assert_eq!(parse_color_or_white(None, Format::Png), None);
        assert_eq!(parse_color_or_white(Some("bad"), Format::Png), Some(Rgba([255, 255, 255, 255])));
        assert_eq!(java_color_decode("-1"), Some(Rgba([255, 255, 255, 255])));
        assert_eq!(java_color_decode("+16711680"), Some(Rgba([255, 0, 0, 255])));
        assert_eq!(java_color_decode("0777"), Some(Rgba([0, 1, 255, 255])));
        assert_eq!(java_color_decode("0"), Some(Rgba([0, 0, 0, 255])));
        assert_eq!(java_color_decode("0x1FFFFFFFF"), None);
        assert_eq!(java_color_decode("#GG"), None);
        // Each writer refuses what it cannot write.
        assert!(encode(DynamicImage::new_rgba8(0, 0), Format::Png).is_err());
        assert!(encode(DynamicImage::new_rgba8(70_000, 1), Format::Jpeg).is_err());
        assert!(encode(DynamicImage::new_rgba8(20_000, 1), Format::Webp).is_err());
        assert!(encode(DynamicImage::new_rgba8(1, 1), Format::General).is_err());
        assert!(is_jpeg(Format::Jpg) && !is_jpeg(Format::Png));
    }
}

//! `ImageTransformUtil` and `ImageDetailsUtil`: the scale, flip, rotate and crop the image
//! editors apply before an upload (`/transform`, `/generic/client`, `/generic/user`,
//! `/generic/resize`).
//!
//! Geometry is the Java service's: the same output sizes, offsets and fill. Pixels are not
//! bit-identical (different resampler and encoders), as with the download transforms.

use std::io::Cursor;

use axum::http::StatusCode;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::imageops::{self, FilterType};
use image::{DynamicImage, ImageEncoder, Rgba, RgbaImage};
use platform::error::AppError;

use crate::spring::safe_bool;

/// `ImageDetails`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageDetails {
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub rotation: Option<i32>,
    pub crop_x: Option<i32>,
    pub crop_y: Option<i32>,
    pub crop_width: Option<i32>,
    pub crop_height: Option<i32>,
    pub flip_horizontal: bool,
    pub flip_vertical: bool,
    pub background: Option<String>,
}

/// `ImageDetailsUtil.makeDetails` from the form's text parts. A part that is not a number is a
/// 400 here; Java's `Integer.valueOf` fails with a 500.
pub fn details_from(get: impl Fn(&str) -> Option<String>) -> Result<ImageDetails, AppError> {
    let int = |k: &str| -> Result<Option<i32>, AppError> {
        match get(k) {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse::<i32>()
                .map(Some)
                .map_err(|_| crate::errors::param_invalid(k, format!("Invalid value '{v}' for '{k}'"))),
        }
    };
    Ok(ImageDetails {
        width: int("width")?,
        height: int("height")?,
        rotation: int("rotation")?,
        crop_x: int("cropAreaX")?,
        crop_y: int("cropAreaY")?,
        crop_width: int("cropAreaWidth")?,
        crop_height: int("cropAreaHeight")?,
        flip_horizontal: safe_bool(get("flipHorizontal").as_deref()),
        flip_vertical: safe_bool(get("flipVertical").as_deref()),
        background: get("backgroundColor"),
    })
}

fn transform_error() -> AppError {
    crate::errors::status(StatusCode::INTERNAL_SERVER_ERROR, crate::errors::IMAGE_TRANSFORM_ERROR, &[])
}

/// `makeSourceImage`: the decoded image; `alpha` is the canvas type the name asks for
/// (`TYPE_INT_ARGB` for a name ending in `png`).
pub fn decode(bytes: &[u8]) -> Result<DynamicImage, AppError> {
    image::load_from_memory(bytes)
        .map_err(|_| crate::errors::literal("FILES.IMAGE_UNREADABLE", StatusCode::INTERNAL_SERVER_ERROR, "Unable to find the reader for the image.").into())
}

pub fn wants_alpha(name: &str) -> bool {
    name.to_lowercase().ends_with("png")
}

/// `transformImage`: scale, flips, rotation, crop, in that order.
pub fn transform(src: DynamicImage, alpha: bool, d: &ImageDetails) -> Result<RgbaImage, AppError> {
    let mut img = scale(src, d.width, d.height).to_rgba8();
    if d.flip_horizontal {
        img = imageops::flip_horizontal(&img);
    }
    if d.flip_vertical {
        img = imageops::flip_vertical(&img);
    }
    if let Some(r) = d.rotation.filter(|r| *r != 0) {
        img = rotate(&img, alpha, r, d.background.as_deref())?;
    }
    if let (Some(x), Some(y), Some(w), Some(h)) = (d.crop_x, d.crop_y, d.crop_width, d.crop_height) {
        img = crop(&img, x, y, w, h, d.background.as_deref(), alpha)?;
    }
    Ok(img)
}

/// `scaleImage`: Scalr's `AUTOMATIC` mode keeps the aspect ratio, fitting the width of a
/// landscape or square image and the height of a portrait one.
fn scale(src: DynamicImage, width: Option<i32>, height: Option<i32>) -> DynamicImage {
    let (sw, sh) = (src.width() as i64, src.height() as i64);
    if (width.is_none() && height.is_none())
        || (width.map(i64::from) == Some(sw) && height.map(i64::from) == Some(sh))
    {
        return src;
    }
    let tw = width.map(i64::from).unwrap_or(sw);
    let th = height.map(i64::from).unwrap_or(sh);
    let ratio = sh as f32 / sw as f32;
    let (nw, nh) = if ratio <= 1.0 {
        if tw == sw {
            return src;
        }
        (tw, (tw as f32 * ratio + 0.5).floor() as i64)
    } else {
        if th == sh {
            return src;
        }
        ((th as f32 / ratio + 0.5).floor() as i64, th)
    };
    src.resize_exact(nw.max(1) as u32, nh.max(1) as u32, FilterType::Lanczos3)
}

/// `getColorFromString`: `#rrggbb` or `#rrggbbaa`; three characters or fewer is transparent.
pub fn color_from_string(s: Option<&str>) -> Result<Rgba<u8>, AppError> {
    let Some(s) = s.filter(|s| s.trim().len() > 3) else { return Ok(Rgba([0, 0, 0, 0])) };
    let s = s.strip_prefix('#').unwrap_or(s);
    let bad = || AppError::Internal(anyhow::anyhow!("For input string: \"{s}\""));
    if s.len() <= 6 {
        let v = i64::from_str_radix(s, 16).map_err(|_| bad())?;
        return Ok(Rgba([(v >> 16) as u8, (v >> 8) as u8, v as u8, 255]));
    }
    let rgb = i64::from_str_radix(s.get(..6).ok_or_else(bad)?, 16).map_err(|_| bad())?;
    let a = i64::from_str_radix(s.get(6..).ok_or_else(bad)?, 16).map_err(|_| bad())?;
    if !(0..=255).contains(&a) {
        return Err(bad());
    }
    Ok(Rgba([(rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8, a as u8]))
}

/// `src` over `dst` (Java2D's default `SrcOver`).
fn over(dst: Rgba<u8>, src: Rgba<u8>) -> Rgba<u8> {
    let sa = src[3] as f32 / 255.0;
    let da = dst[3] as f32 / 255.0;
    let oa = sa + da * (1.0 - sa);
    if oa <= 0.0 {
        return Rgba([0, 0, 0, 0]);
    }
    let ch = |i: usize| ((src[i] as f32 * sa + dst[i] as f32 * da * (1.0 - sa)) / oa).round() as u8;
    Rgba([ch(0), ch(1), ch(2), (oa * 255.0).round() as u8])
}

/// A new canvas: transparent for `TYPE_INT_ARGB`, black (opaque) for `TYPE_INT_RGB`.
fn canvas(w: u32, h: u32, alpha: bool) -> RgbaImage {
    RgbaImage::from_pixel(w.max(1), h.max(1), if alpha { Rgba([0, 0, 0, 0]) } else { Rgba([0, 0, 0, 255]) })
}

fn fill(img: &mut RgbaImage, w: u32, h: u32, c: Rgba<u8>) {
    for y in 0..h.min(img.height()) {
        for x in 0..w.min(img.width()) {
            let p = img.get_pixel(x, y);
            img.put_pixel(x, y, over(*p, c));
        }
    }
}

/// `rotateImage`: a canvas big enough for the rotated image, filled unless it has alpha, the
/// image drawn rotated about the canvas centre.
fn rotate(src: &RgbaImage, alpha: bool, degrees: i32, bg: Option<&str>) -> Result<RgbaImage, AppError> {
    let rad = (degrees as f64).to_radians();
    let (sw, sh) = (src.width() as f64, src.height() as f64);
    let w = ((sw * rad.cos()).abs() + (sh * rad.sin()).abs()) as i64;
    let h = ((sw * rad.sin()).abs() + (sh * rad.cos()).abs()) as i64;
    if w <= 0 || h <= 0 {
        return Err(transform_error());
    }
    let mut out = canvas(w as u32, h as u32, alpha);
    if !alpha {
        let c = if bg.is_none_or(|b| b.trim().is_empty()) { Rgba([0, 0, 0, 255]) } else { color_from_string(bg)? };
        fill(&mut out, w as u32, h as u32, c);
    }
    // Java: x = -1 * (W - w) / 2 in int arithmetic, then rotate about (w/2, h/2).
    let ox = (-(src.width() as i64 - w)) / 2;
    let oy = (-(src.height() as i64 - h)) / 2;
    let (cx, cy) = (w as f64 / 2.0, h as f64 / 2.0);
    let (cos, sin) = (rad.cos(), rad.sin());
    for py in 0..h as u32 {
        for px in 0..w as u32 {
            let (dx, dy) = (px as f64 + 0.5 - cx, py as f64 + 0.5 - cy);
            // Inverse rotation back into the unrotated drawing space.
            let ux = dx * cos + dy * sin + cx - ox as f64 - 0.5;
            let uy = -dx * sin + dy * cos + cy - oy as f64 - 0.5;
            if let Some(s) = sample(src, ux, uy) {
                let d = *out.get_pixel(px, py);
                out.put_pixel(px, py, over(d, s));
            }
        }
    }
    Ok(out)
}

/// Bilinear sample at a pixel-centre coordinate; `None` outside the image.
fn sample(img: &RgbaImage, x: f64, y: f64) -> Option<Rgba<u8>> {
    let (w, h) = (img.width() as f64, img.height() as f64);
    if x < -0.5 || y < -0.5 || x > w - 0.5 || y > h - 0.5 {
        return None;
    }
    let x = x.clamp(0.0, w - 1.0);
    let y = y.clamp(0.0, h - 1.0);
    let (x0, y0) = (x.floor() as u32, y.floor() as u32);
    let (x1, y1) = ((x0 + 1).min(img.width() - 1), (y0 + 1).min(img.height() - 1));
    let (fx, fy) = (x - x0 as f64, y - y0 as f64);
    let p = |xx, yy| *img.get_pixel(xx, yy);
    let (a, b, c, d) = (p(x0, y0), p(x1, y0), p(x0, y1), p(x1, y1));
    let mut o = [0u8; 4];
    for i in 0..4 {
        let top = a[i] as f64 * (1.0 - fx) + b[i] as f64 * fx;
        let bot = c[i] as f64 * (1.0 - fx) + d[i] as f64 * fx;
        o[i] = (top * (1.0 - fy) + bot * fy).round() as u8;
    }
    Some(Rgba(o))
}

/// `cropImage`: a `width` x `height` canvas with the part of the image inside the crop drawn at
/// the offset a negative origin leaves; outside the image is the fill (black by default) on an
/// opaque canvas and transparent on one with alpha.
fn crop(src: &RgbaImage, x: i32, y: i32, width: i32, height: i32, bg: Option<&str>, alpha: bool) -> Result<RgbaImage, AppError> {
    let (sw, sh) = (src.width() as i64, src.height() as i64);
    let (x, y, width, height) = (x as i64, y as i64, width as i64, height as i64);
    let nx = x.max(0);
    let ny = y.max(0);
    let mut nw = if x < 0 { width + x } else { width };
    let mut nh = if y < 0 { height + y } else { height };
    if nx + nw > sw {
        nw = sw - nx;
    }
    if ny + nh > sh {
        nh = sh - ny;
    }
    // `getSubimage` refuses an empty or out-of-range area.
    if nw <= 0 || nh <= 0 || width <= 0 || height <= 0 || nx >= sw || ny >= sh {
        return Err(transform_error());
    }
    let part = imageops::crop_imm(src, nx as u32, ny as u32, nw as u32, nh as u32).to_image();
    let mut out = canvas(width as u32, height as u32, alpha);
    if !alpha {
        let c = if bg.is_none_or(|b| b.trim().is_empty()) { Rgba([0, 0, 0, 255]) } else { color_from_string(bg)? };
        fill(&mut out, nw as u32, nh as u32, c);
    }
    let (dx, dy) = (if x < 0 { -x } else { 0 }, if y < 0 { -y } else { 0 });
    for (px, py, p) in part.enumerate_pixels() {
        let (tx, ty) = (px as i64 + dx, py as i64 + dy);
        if tx < width && ty < height {
            let d = *out.get_pixel(tx as u32, ty as u32);
            out.put_pixel(tx as u32, ty as u32, over(d, *p));
        }
    }
    Ok(out)
}

/// PNG (with alpha when the image has it) or JPEG at quality 75 (alpha laid over black, as
/// drawing onto an RGB image does).
pub fn encode(img: &RgbaImage, png: bool) -> Result<Vec<u8>, AppError> {
    let mut out = Cursor::new(Vec::new());
    let r = if png {
        PngEncoder::new(&mut out).write_image(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgba8)
    } else {
        let mut rgb = image::RgbImage::new(img.width(), img.height());
        for (x, y, p) in img.enumerate_pixels() {
            let a = p[3] as u32;
            rgb.put_pixel(x, y, image::Rgb([(p[0] as u32 * a / 255) as u8, (p[1] as u32 * a / 255) as u8, (p[2] as u32 * a / 255) as u8]));
        }
        JpegEncoder::new_with_quality(&mut out, 75).write_image(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8)
    };
    r.map_err(|_| transform_error())?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(w: u32, h: u32) -> DynamicImage {
        DynamicImage::ImageRgba8(RgbaImage::from_pixel(w, h, Rgba([10, 200, 10, 255])))
    }

    fn d() -> ImageDetails {
        ImageDetails::default()
    }

    #[test]
    fn scalr_automatic_geometry() {
        let out = transform(img(400, 200), false, &ImageDetails { width: Some(100), height: Some(10), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (100, 50));
        let out = transform(img(200, 400), false, &ImageDetails { width: Some(10), height: Some(100), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (50, 100));
        // A landscape image already at the target width is left alone, whatever the height says.
        let out = transform(img(400, 200), false, &ImageDetails { width: Some(400), height: Some(10), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (400, 200));
    }

    #[test]
    fn rotation_canvas_size() {
        let out = transform(img(40, 20), false, &ImageDetails { rotation: Some(90), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (20, 40));
        let out = transform(img(40, 20), true, &ImageDetails { rotation: Some(45), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (42, 42));
        // Corners of a 45 degree rotation on an alpha canvas stay transparent.
        assert_eq!(out.get_pixel(0, 0)[3], 0);
    }

    #[test]
    fn crop_with_negative_origin_and_fill() {
        let details = ImageDetails {
            crop_x: Some(-5),
            crop_y: Some(0),
            crop_width: Some(20),
            crop_height: Some(10),
            background: Some("#ff0000".into()),
            ..d()
        };
        let out = transform(img(40, 20), false, &details).unwrap();
        assert_eq!(out.dimensions(), (20, 10));
        // Java fills only (0,0)-(newWidth,newHeight), then draws the image at x=5.
        assert_eq!(*out.get_pixel(0, 0), Rgba([255, 0, 0, 255]));
        assert_eq!(*out.get_pixel(10, 5), Rgba([10, 200, 10, 255]));
        assert!(transform(img(10, 10), false, &ImageDetails { crop_x: Some(20), crop_y: Some(0), crop_width: Some(5), crop_height: Some(5), ..d() }).is_err());
    }

    #[test]
    fn colors() {
        assert_eq!(color_from_string(Some("#ff")).unwrap(), Rgba([0, 0, 0, 0]));
        // Four characters is not "three or fewer": "#fff" is 0x000fff, as Java reads it.
        assert_eq!(color_from_string(Some("#fff")).unwrap(), Rgba([0, 15, 255, 255]));
        assert_eq!(color_from_string(Some("#00ff00")).unwrap(), Rgba([0, 255, 0, 255]));
        assert_eq!(color_from_string(Some("#00ff0080")).unwrap(), Rgba([0, 255, 0, 128]));
        assert!(color_from_string(Some("#zzzzzz")).is_err());
    }

    #[test]
    fn details_parse() {
        let parts = [("width", "10"), ("flipHorizontal", "true")];
        let dd = details_from(|k| parts.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())).unwrap();
        assert_eq!(dd.width, Some(10));
        assert!(dd.flip_horizontal && !dd.flip_vertical);
        assert!(details_from(|k| (k == "height").then(|| "x".to_string())).is_err());
    }


    #[test]
    fn portraits_transparency_and_crops_past_the_edge() {
        // A portrait image already at the target height is left alone.
        let out = transform(img(200, 400), false, &ImageDetails { width: Some(10), height: Some(400), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (200, 400));
        // The same size asked for is no scaling.
        let out = transform(img(20, 10), false, &ImageDetails { width: Some(20), height: Some(10), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (20, 10));
        // Transparent over transparent stays transparent.
        let clear = DynamicImage::ImageRgba8(RgbaImage::from_pixel(4, 4, Rgba([0, 0, 0, 0])));
        let out = transform(clear, true, &ImageDetails { rotation: Some(30), ..d() }).unwrap();
        assert!(out.pixels().all(|p| p[3] == 0));
        // An opaque canvas is filled: black by default, else the background.
        let out = transform(img(4, 2), false, &ImageDetails { rotation: Some(45), ..d() }).unwrap();
        assert_eq!(out.get_pixel(0, 0)[3], 255);
        let out = transform(img(4, 2), false, &ImageDetails { rotation: Some(45), background: Some("#0000ff".into()), ..d() }).unwrap();
        assert_eq!(*out.get_pixel(0, 0), Rgba([0, 0, 255, 255]));
        assert!(transform(img(4, 2), false, &ImageDetails { rotation: Some(45), background: Some("#nothex".into()), ..d() }).is_err());
        // A crop running past the bottom edge keeps what is there.
        let crop = ImageDetails { crop_x: Some(0), crop_y: Some(5), crop_width: Some(10), crop_height: Some(100), ..d() };
        let out = transform(img(40, 20), true, &crop).unwrap();
        assert_eq!(out.dimensions(), (10, 100));
        assert_eq!(out.get_pixel(0, 14)[3], 255);
        assert_eq!(out.get_pixel(0, 15)[3], 0);
        let out = transform(img(40, 20), false, &ImageDetails { crop_y: Some(-3), crop_x: Some(30), crop_width: Some(20), crop_height: Some(5), ..d() }).unwrap();
        assert_eq!(out.dimensions(), (20, 5));
        assert!(transform(img(40, 20), false, &ImageDetails { crop_x: Some(0), crop_y: Some(0), crop_width: Some(0), crop_height: Some(5), ..d() }).is_err());
        assert!(transform(img(40, 20), false, &ImageDetails { crop_x: Some(0), crop_y: Some(0), crop_width: Some(5), crop_height: Some(5), background: Some("#xyzxyz".into()), ..d() }).is_err());
        // A flip each way.
        let out = transform(img(3, 2), true, &ImageDetails { flip_horizontal: true, flip_vertical: true, ..d() }).unwrap();
        assert_eq!(out.dimensions(), (3, 2));
    }

    #[test]
    fn colors_with_alpha_and_encoders() {
        assert!(color_from_string(Some("#00ff00fff")).is_err());
        assert!(color_from_string(Some("#00ff00zz")).is_err());
        assert_eq!(color_from_string(None).unwrap(), Rgba([0, 0, 0, 0]));
        assert!(wants_alpha("A.PNG") && !wants_alpha("a.jpg"));
        assert!(decode(b"nope").is_err());
        let half = RgbaImage::from_pixel(2, 2, Rgba([200, 100, 50, 128]));
        let jpeg = encode(&half, false).unwrap();
        assert_eq!(image::guess_format(&jpeg).unwrap(), image::ImageFormat::Jpeg);
        assert!(encode(&RgbaImage::new(70_000, 1), false).is_err());
        assert_eq!(over(Rgba([0, 0, 0, 0]), Rgba([0, 0, 0, 0])), Rgba([0, 0, 0, 0]));
    }
}

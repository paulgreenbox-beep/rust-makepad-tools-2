//! Shared bounded native-PNG observation, independent of host/guest transport.
use super::protocol::{RemoteError, Result};
use serde_json::json;
use std::{collections::BTreeSet, io::Cursor};

pub(super) struct PngObservation {
    pub width: u32,
    pub height: u32,
    pub sampled_colors: usize,
}

pub(super) fn inspect_png(bytes: &[u8]) -> Result<PngObservation> {
    let fail = RemoteError::refused;
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err(fail("NATIVE_CAPTURE_SIZE_REFUSED"));
    }
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|_| fail("NATIVE_PNG_INVALID"))?;
    let (width, height) = (reader.info().width, reader.info().height);
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return Err(fail("NATIVE_CAPTURE_DIMENSIONS_REFUSED"));
    }
    let size = reader
        .output_buffer_size()
        .filter(|n| *n <= 64 * 1024 * 1024)
        .ok_or_else(|| fail("NATIVE_PNG_DECODE_BUDGET_EXCEEDED"))?;
    let mut pixels = vec![0; size];
    let info = reader
        .next_frame(&mut pixels)
        .map_err(|_| fail("NATIVE_PNG_INVALID"))?;
    let sampled_colors = pixels[..info.buffer_size()]
        .chunks(info.color_type.samples())
        .step_by(32)
        .take(20000)
        .collect::<BTreeSet<_>>()
        .len();
    if sampled_colors <= 16 {
        let mut error = fail("NATIVE_CAPTURE_BLANK");
        error.details["native_png_observation"] = json!({
            "width": info.width, "height": info.height, "sampled_colors": sampled_colors,
            "stride": 32, "max_samples": 20000,
        });
        return Err(error);
    }
    Ok(PngObservation {
        width: info.width,
        height: info.height,
        sampled_colors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded(blank: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut encoder = png::Encoder::new(&mut data, 128, 32);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        let pixels = (0..128 * 32)
            .flat_map(|i| {
                if blank {
                    [0, 0, 0]
                } else {
                    [(i / 32) as u8, (i / 128) as u8, (i % 255) as u8]
                }
            })
            .collect::<Vec<_>>();
        writer.write_image_data(&pixels).unwrap();
        drop(writer);
        data
    }
    #[test]
    fn native_png_observation_decodes_real_pixels_with_bounded_dimensions() {
        let value = inspect_png(&encoded(false)).unwrap();
        assert_eq!((value.width, value.height), (128, 32));
        assert!(value.sampled_colors > 16);
    }
    #[test]
    fn native_png_blank_error_retains_bounded_observation_and_refusal() {
        let error = inspect_png(&encoded(true)).err().unwrap();
        assert_eq!(error.code, "NATIVE_CAPTURE_BLANK");
        assert_eq!(error.outcome, "NOT_DISPATCHED");
        assert!(!error.retry_safe);
        assert_eq!(error.details["automatic_retry_allowed"], false);
        assert_eq!(error.details["native_png_observation"], json!({
            "width": 128, "height": 32, "sampled_colors": 1,
            "stride": 32, "max_samples": 20000,
        }));
    }
    #[test]
    fn native_png_observation_refuses_blank_truncated_and_oversized_bytes() {
        assert_eq!(
            inspect_png(&encoded(true)).err().unwrap().code,
            "NATIVE_CAPTURE_BLANK"
        );
        assert_eq!(
            inspect_png(b"not png").err().unwrap().code,
            "NATIVE_PNG_INVALID"
        );
        let mut data = encoded(false);
        data.truncate(data.len() / 2);
        assert_eq!(inspect_png(&data).err().unwrap().code, "NATIVE_PNG_INVALID");
        assert_eq!(
            inspect_png(&vec![0; 16 * 1024 * 1024 + 1])
                .err()
                .unwrap()
                .code,
            "NATIVE_CAPTURE_SIZE_REFUSED"
        );
    }
}

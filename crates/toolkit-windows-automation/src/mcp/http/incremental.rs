//! Private, negotiated image transport. Not an MCP tool or a second capture owner.
use super::{prepare_capture, read_bounded};
use crate::frame_delta::{FrameDeltaStream, FrameIdentity, FrameMode, FramePacket, RgbaFrame};
use crate::{CaptureResult, GuiToolRegistry};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Cursor, path::Path, time::Instant};

pub(super) const CAPABILITY: &str = "toolkit.incrementalCapture";
pub(super) const METHOD: &str = "toolkit/captureFrame";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    window_id: String,
    #[serde(default)]
    ack: Option<Ack>,
    #[serde(default)]
    reset: bool,
    #[serde(default)]
    full_only: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack { frame_id: u64, pixel_sha256: String }

pub(super) fn negotiated(init: &Value) -> bool {
    init["params"]["capabilities"]["experimental"][CAPABILITY]["version"].as_u64() == Some(1)
}

pub(super) struct FrameTransport {
    enabled: bool,
    owner: String,
    // One stream per client; switching windows resets rather than accumulating caches.
    stream: Option<FrameDeltaStream>,
}
impl FrameTransport {
    pub(super) fn new(owner: String, enabled: bool) -> Self { Self { owner, enabled, stream:None } }

    pub(super) fn dispatch(&mut self, registry: &mut GuiToolRegistry, request: &Value,
        evidence: &Path, capture_sequence: &mut u64) -> Option<Value> {
        if request["method"] != METHOD { return None; }
        let id = request["id"].clone();
        if !self.enabled {
            return Some(super::json_rpc_error(id, -32601, "Incremental capture was not negotiated", json!({"code":"CAPABILITY_NOT_NEGOTIATED"})));
        }
        Some(match self.capture(registry, request, evidence, capture_sequence) {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(message) => super::json_rpc_error(id, -32000, "Incremental capture refused",
                json!({"code":message,"retry_safe":false})),
        })
    }

    fn capture(&mut self, registry: &mut GuiToolRegistry, request: &Value,
        evidence: &Path, capture_sequence: &mut u64) -> Result<Value, String> {
        let params: Params = serde_json::from_value(request["params"].clone()).map_err(|_| "INVALID_ARGUMENT".to_owned())?;
        if params.window_id.is_empty() || params.window_id.len() > 512 { return Err("INVALID_WINDOW_ID".into()); }
        if let Some(stream) = self.stream.as_mut() {
            if params.reset {
                return stream.require_reset().map(|p| packet_value(&p, None, 0, stream.cached_bytes()))
                    .map_err(|e| format!("{e:?}"));
            }
            if let Some(ack) = params.ack.as_ref() {
                if ack.pixel_sha256.len() != 64 { return Err("INVALID_ACK_HASH".into()); }
                if stream.acknowledge(ack.frame_id, &ack.pixel_sha256).is_err() {
                    return stream.require_reset().map(|p| packet_value(&p, None, 0, stream.cached_bytes()))
                        .map_err(|e| format!("{e:?}"));
                }
            }
            if params.full_only { stream.cleanup(); }
        } else if params.ack.is_some() { return Err("MISSING_BASE_FRAME".into()); }

        let started = Instant::now();
        let mut capture_request = json!({"params":{"arguments":{"window_id":params.window_id}}});
        prepare_capture(&mut capture_request, evidence, capture_sequence).map_err(str::to_owned)?;
        let captured = registry.invoke("windows_capture_window", capture_request["params"]["arguments"].clone());
        if !captured.ok { return Err(format!("CAPTURE_FAILED:{:?}", captured.error.map(|e|e.code))); }
        let capture: CaptureResult = serde_json::from_value(captured.result.ok_or("CAPTURE_RESULT_MISSING")?)
            .map_err(|_| "CAPTURE_RESULT_INVALID")?;
        let source_path = Path::new(&capture.path);
        if source_path.parent() != Some(evidence) { return Err("EVIDENCE_ROOT_MISMATCH".into()); }
        let png = read_bounded(source_path, 64 * 1024 * 1024).map_err(|_| "SOURCE_PNG_READ_FAILED")?;
        let frame = decode_rgba(&png)?;
        if frame.width() != capture.image_width || frame.height() != capture.image_height {
            return Err("CAPTURE_DIMENSIONS_MISMATCH".into());
        }
        let geometry = capture.geometry.as_ref().ok_or("COORDINATE_MAPPING_UNVERIFIED")?;
        let identity = FrameIdentity {
            owner:self.owner.clone(), session_id:format!("{}:capture",self.owner), window_id:capture.window_id.clone(),
            capture_id:format!("{}:{}",capture.hwnd,capture.backend), process_id:capture.pid,
            process_birth:geometry.process_birth, geometry_generation:geometry.geometry_generation,
        };
        if self.stream.is_none() { self.stream=Some(FrameDeltaStream::new(identity.clone()).map_err(|e|format!("{e:?}"))?); }
        let capture_micros = started.elapsed().as_micros();
        let stream=self.stream.as_mut().ok_or("STREAM_UNAVAILABLE")?;
        let mut packet=stream.push(&identity,frame).map_err(|e|format!("{e:?}"))?;
        let mut payload=packet_value(&packet,Some(&capture),capture_micros,stream.cached_bytes());
        if packet.mode == FrameMode::Delta {
            let delta_size=serde_json::to_vec(&payload).map_err(|_|"SERIALIZATION_FAILED")?.len();
            packet.mode=FrameMode::Full;
            let mut full=packet_value(&packet,Some(&capture),capture_micros,stream.cached_bytes());
            let full_size=serde_json::to_vec(&full).map_err(|_|"SERIALIZATION_FAILED")?.len();
            if delta_size >= full_size {
                full["fallback_reason"] = json!("DELTA_WIRE_NOT_CHEAPER"); payload=full;
            } else { packet.mode=FrameMode::Delta; }
        }
        // Original source full PNG is always authoritative; this canonical PNG
        // is separately retained because encoder settings can change PNG bytes.
        if !packet.full_png.is_empty() {
            fs::write(evidence.join(format!("frame-{}-full.png",packet.frame_id)),&packet.full_png)
                .map_err(|_|"FULL_EVIDENCE_WRITE_FAILED")?;
        }
        for (i,patch) in packet.patches.iter().enumerate() {
            fs::write(evidence.join(format!("frame-{}-patch-{i}.png",packet.frame_id)),&patch.png_bytes)
                .map_err(|_|"PATCH_EVIDENCE_WRITE_FAILED")?;
        }
        payload["source_full_png_sha256"] = json!(format!("{:x}",Sha256::digest(&png)));
        fs::write(evidence.join(format!("frame-{}.json",packet.frame_id)),serde_json::to_vec_pretty(&payload).map_err(|_|"SERIALIZATION_FAILED")?)
            .map_err(|_|"FRAME_EVIDENCE_WRITE_FAILED")?;
        Ok(payload)
    }
}

fn packet_value(p: &FramePacket, capture: Option<&CaptureResult>, capture_micros:u128, cached:usize) -> Value {
    let mode=match p.mode { FrameMode::Full=>"FULL",FrameMode::Delta=>"DELTA",FrameMode::NoChange=>"NO_CHANGE",FrameMode::ResetRequired=>"RESET_REQUIRED" };
    let mut result=json!({"version":1,"mode":mode,"frame_id":p.frame_id,"base_frame_id":p.base_frame_id,
        "base_pixel_sha256":p.base_pixel_sha256,"full_frame_sha256":p.pixel_sha256,"full_png_sha256":p.png_sha256,
        "width":p.width,"height":p.height,"pixel_format":"RGBA8","coordinate_space":"CAPTURE_PIXEL",
        "geometry_generation":p.identity.geometry_generation,"window_id":p.identity.window_id,
        "reset_reason":p.reset_reason.map(|r|format!("{r:?}")),"cached_bytes":cached,
        "timings":{"capture_and_decode_micros":capture_micros,"compare_micros":p.timings.compare_micros,
            "full_png_encode_micros":p.timings.full_png_encode_micros,"patch_png_encode_micros":p.timings.patch_png_encode_micros}});
    if p.mode == FrameMode::Full || p.mode == FrameMode::ResetRequired {
        result["base_frame_id"]=Value::Null; result["base_pixel_sha256"]=Value::Null;
    }
    if let Some(c)=capture {
        result["source_full_png_path"]=json!(c.path); result["capture_timestamp_unix_ms"]=json!(c.timestamp_unix_ms);
        result["geometry"]=json!(c.geometry);
    }
    match p.mode {
        FrameMode::Full=> {result["image_base64"]=json!(STANDARD.encode(&p.full_png));}
        FrameMode::Delta=> {result["rectangles"]=json!(p.patches.iter().map(|patch|json!({
            "x":patch.rect.x,"y":patch.rect.y,"width":patch.rect.width,"height":patch.rect.height,
            "png_sha256":patch.png_sha256,"image_base64":STANDARD.encode(&patch.png_bytes)})).collect::<Vec<_>>());}
        _=>{}
    }
    result
}

fn decode_rgba(bytes:&[u8])->Result<RgbaFrame,String> {
    let mut decoder=png::Decoder::new(Cursor::new(bytes));
    decoder.set_limits(png::Limits{bytes:64*1024*1024});
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader=decoder.read_info().map_err(|_|"INVALID_SOURCE_PNG")?;
    let info=reader.info();
    (info.width as usize).checked_mul(info.height as usize).and_then(|n|n.checked_mul(4))
        .filter(|n|*n>0 && *n<=64*1024*1024).ok_or("PNG_DECODE_BUDGET")?;
    let size=reader.output_buffer_size().filter(|n|*n<=64*1024*1024).ok_or("PNG_DECODE_BUDGET")?;
    let mut pixels=vec![0;size];
    let info=reader.next_frame(&mut pixels).map_err(|_|"INVALID_SOURCE_PNG")?;
    pixels.truncate(info.buffer_size());
    let rgba=match (info.color_type,info.bit_depth) {
        (png::ColorType::Rgba,png::BitDepth::Eight)=>pixels,
        (png::ColorType::Rgb,png::BitDepth::Eight)=>pixels.chunks_exact(3).flat_map(|p|[p[0],p[1],p[2],255]).collect(),
        _=>return Err("UNSUPPORTED_SOURCE_PIXEL_FORMAT".into()),
    };
    RgbaFrame::new(info.width,info.height,rgba).map_err(|e|format!("{e:?}"))
}

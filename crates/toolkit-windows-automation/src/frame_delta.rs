//! Per-client, lossless screenshot frame deltas over decoded RGBA8 capture pixels.
//!
//! This module is deliberately transport- and capture-backend-neutral. Create one
//! [`FrameDeltaStream`] per owner/session/window stream; it never owns a global
//! "last screenshot". A receiver must apply each packet and ACK its frame ID plus
//! decoded-pixel SHA-256 before the producer may use it as the next delta base.
//! The stream retains at most one acknowledged base and one outstanding decoded
//! frame, with their aggregate decoded-frame cache bounded to 8 MiB by default
//! and 64 MiB maximum. Full PNG and patch PNG digests are distinct from decoded-
//! pixel hashes.
//! With one default stream per worker, 32 workers retain at most 256 MiB of
//! decoded stream-cache pixels. This bound excludes caller-owned input frames,
//! returned PNG packets, and transport serialization buffers.

use png::{BitDepth, ColorType};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Cursor, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const FRAME_DELTA_BLOCK_SIZE: u32 = 64;
pub const FRAME_DELTA_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const FRAME_DELTA_MAX_RECTANGLES: usize = 128;
pub const FRAME_DELTA_DEFAULT_CACHE_BYTES: usize = 8 * 1024 * 1024;

// Approximate private-HTTP JSON overhead, including Base64 expansion for image
// blobs. The transport still must measure its actual serialized response bytes.
const FULL_METADATA_ESTIMATE_BYTES: usize = 48;
const DELTA_METADATA_ESTIMATE_BYTES: usize = 64;
const RECT_METADATA_ESTIMATE_BYTES: usize = 40;
const MAX_IDENTITY_FIELD_BYTES: usize = 512;

/// Identity that scopes one client's independent frame history.
///
/// `capture_id` identifies the capture source, not a particular frame. A changed
/// window, capture source, process birth, or geometry generation forces a reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameIdentity {
    pub owner: String,
    pub session_id: String,
    pub window_id: String,
    pub capture_id: String,
    pub process_id: u32,
    pub process_birth: u64,
    pub geometry_generation: u64,
}

impl FrameIdentity {
    fn validate(&self) -> Result<(), FrameDeltaError> {
        for (name, value) in [
            ("owner", self.owner.as_str()),
            ("session_id", self.session_id.as_str()),
            ("window_id", self.window_id.as_str()),
            ("capture_id", self.capture_id.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_IDENTITY_FIELD_BYTES {
                return Err(FrameDeltaError::InvalidIdentity(name));
            }
        }
        if self.process_id == 0 || self.process_birth == 0 {
            return Err(FrameDeltaError::InvalidIdentity("process identity"));
        }
        Ok(())
    }

    fn change_reason(&self, other: &Self) -> ResetReason {
        if self.geometry_generation != other.geometry_generation {
            ResetReason::GeometryChanged
        } else {
            ResetReason::IdentityChanged
        }
    }
}

/// An owned, tightly packed decoded RGBA8 frame in capture-pixel coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RgbaFrame {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

impl RgbaFrame {
    pub fn new(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self, FrameDeltaError> {
        let expected = rgba_byte_len(width, height)?;
        if pixels.len() != expected {
            return Err(FrameDeltaError::InvalidPixelBufferLength {
                expected,
                actual: pixels.len(),
            });
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub fn pixel_sha256(&self) -> String {
        sha256_hex(&self.pixels)
    }

    fn byte_len(&self) -> usize {
        self.pixels.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    Rgba8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateSpace {
    CapturePixel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameMode {
    Full,
    Delta,
    NoChange,
    ResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResetReason {
    IdentityChanged,
    GeometryChanged,
    DimensionsChanged,
    UnacknowledgedFrame,
    ClientContextLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePatch {
    pub rect: FrameRect,
    /// A lossless PNG containing exactly `rect.width × rect.height` RGBA8 pixels.
    pub png_bytes: Vec<u8>,
    /// SHA-256 of the PNG blob, distinct from the decoded patch-pixel digest.
    pub png_sha256: String,
    pub pixel_sha256: String,
}

#[derive(Clone, Copy, Debug)]
pub enum FrameWirePayload<'a> {
    Full(&'a [u8]),
    Delta(&'a [FramePatch]),
    NoImage,
}

/// Producer-side measurements. Capture/readback time is deliberately excluded:
/// this engine starts from an already decoded full frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameTimings {
    pub compare_micros: u64,
    pub hash_micros: u64,
    pub full_png_encode_micros: u64,
    pub patch_png_encode_micros: u64,
}

/// A single sequenced result. `full_png` is always a canonical lossless PNG
/// encoded from the complete decoded capture, kept available for authoritative
/// full-frame evidence. Its PNG bytes need not match the producer's original PNG
/// encoding byte-for-byte. A
/// private transport must serialize image bytes by `mode`: FULL sends this PNG,
/// DELTA sends only `patches`, and NO_CHANGE sends no image bytes. In particular,
/// do not serialize `full_png` on DELTA/NO_CHANGE. The mode-specific helper
/// `incremental_image_bytes` reports image-payload bytes only, not RPC metadata.
/// `png_sha256` identifies `full_png`; `pixel_sha256` identifies decoded RGBA8.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FramePacket {
    pub frame_id: u64,
    pub mode: FrameMode,
    pub identity: FrameIdentity,
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub coordinate_space: CoordinateSpace,
    pub base_frame_id: Option<u64>,
    pub base_pixel_sha256: Option<String>,
    pub pixel_sha256: String,
    pub png_sha256: String,
    pub full_png: Vec<u8>,
    pub patches: Vec<FramePatch>,
    pub reset_reason: Option<ResetReason>,
    pub timings: FrameTimings,
}

impl FramePacket {
    /// PNG bytes for a FULL-only transport baseline; zero for RESET_REQUIRED.
    pub fn full_only_image_bytes(&self) -> usize {
        if self.mode == FrameMode::ResetRequired {
            0
        } else {
            self.full_png.len()
        }
    }

    /// Mode-selected image payload bytes; excludes Base64 and RPC metadata.
    pub fn incremental_image_bytes(&self) -> usize {
        match self.wire_payload() {
            FrameWirePayload::Full(bytes) => bytes.len(),
            FrameWirePayload::Delta(patches) => patches.iter().fold(0usize, |sum, patch| {
                sum.saturating_add(patch.png_bytes.len())
            }),
            FrameWirePayload::NoImage => 0,
        }
    }

    /// Mode-selected image vectors for a transport serializer. This deliberately
    /// excludes the authoritative `full_png` field on DELTA and NO_CHANGE.
    pub fn wire_payload(&self) -> FrameWirePayload<'_> {
        match self.mode {
            FrameMode::Full => FrameWirePayload::Full(&self.full_png),
            FrameMode::Delta => FrameWirePayload::Delta(&self.patches),
            FrameMode::NoChange | FrameMode::ResetRequired => FrameWirePayload::NoImage,
        }
    }
}

/// The ACK is bound to both the exact frame sequence and decoded full-frame hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameAck {
    pub frame_id: u64,
    pub pixel_sha256: String,
    /// Local receiver measurement; the protocol ACK identity is still ID + SHA.
    pub reconstruction_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameDeltaConfig {
    /// Maximum connected changed-block rectangles; values above 128 are refused.
    pub max_rectangles: usize,
    /// Aggregate decoded base + outstanding frame cache; defaults to 8 MiB,
    /// with an absolute per-stream ceiling of 64 MiB.
    pub max_cached_bytes: usize,
}

impl Default for FrameDeltaConfig {
    fn default() -> Self {
        Self {
            max_rectangles: FRAME_DELTA_MAX_RECTANGLES,
            max_cached_bytes: FRAME_DELTA_DEFAULT_CACHE_BYTES,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum FrameDeltaError {
    InvalidIdentity(&'static str),
    ForeignOwner,
    ForeignSession,
    InvalidDimensions,
    InvalidPixelBufferLength {
        expected: usize,
        actual: usize,
    },
    FrameTooLarge,
    /// The decoded input exceeds this stream's cache budget and is not retained.
    /// A caller may choose a separate bounded FULL/no-cache path or refuse it.
    FrameExceedsCacheLimit,
    InvalidConfiguration,
    SequenceExhausted,
    UnexpectedAcknowledgement,
    AcknowledgementHashMismatch,
    OutOfOrderFrame,
    MissingBaseFrame,
    WrongBaseFrame,
    WrongBaseHash,
    IdentityMismatch,
    InvalidPacket,
    WrongBaseDimensions,
    PatchOutOfBounds,
    OverlappingPatches,
    WrongPatchDimensions,
    PatchPixelHashMismatch,
    PixelHashMismatch,
    PngHashMismatch,
    PngPayloadTooLarge,
    PngEncodeFailed(String),
    PngDecodeFailed(String),
    InvalidPngFormat,
}

impl fmt::Display for FrameDeltaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for FrameDeltaError {}

struct StoredFrame {
    id: u64,
    frame: RgbaFrame,
    pixel_sha256: String,
    png_sha256: String,
}

struct OutstandingFrame {
    id: u64,
    pixel_sha256: String,
    png_sha256: String,
    /// None means NO_CHANGE, which advances the logical base ID without pixels.
    frame: Option<RgbaFrame>,
}

/// One bounded state machine per client/window stream. It never shares frames
/// with another instance and permits only one unacknowledged response at a time.
pub struct FrameDeltaStream {
    identity: FrameIdentity,
    config: FrameDeltaConfig,
    next_frame_id: u64,
    acknowledged: Option<StoredFrame>,
    outstanding: Option<OutstandingFrame>,
}

impl FrameDeltaStream {
    pub fn new(identity: FrameIdentity) -> Result<Self, FrameDeltaError> {
        Self::with_config(identity, FrameDeltaConfig::default())
    }

    pub fn with_config(
        identity: FrameIdentity,
        config: FrameDeltaConfig,
    ) -> Result<Self, FrameDeltaError> {
        identity.validate()?;
        if config.max_rectangles == 0
            || config.max_rectangles > FRAME_DELTA_MAX_RECTANGLES
            || config.max_cached_bytes == 0
            || config.max_cached_bytes > FRAME_DELTA_MAX_FRAME_BYTES
        {
            return Err(FrameDeltaError::InvalidConfiguration);
        }
        Ok(Self {
            identity,
            config,
            next_frame_id: 1,
            acknowledged: None,
            outstanding: None,
        })
    }

    pub fn identity(&self) -> &FrameIdentity {
        &self.identity
    }

    /// Bytes retained as decoded full-frame cache (base plus outstanding frame).
    pub fn cached_bytes(&self) -> usize {
        let base = self
            .acknowledged
            .as_ref()
            .map_or(0, |stored| stored.frame.byte_len());
        let pending = self
            .outstanding
            .as_ref()
            .and_then(|stored| stored.frame.as_ref())
            .map_or(0, RgbaFrame::byte_len);
        base.saturating_add(pending)
    }

    /// Compare a complete decoded capture to the last ACKed frame.
    ///
    /// A target identity or dimension change emits RESET_REQUIRED and discards
    /// this input; the caller must submit a fresh frame for the following FULL.
    /// If a prior packet is still outstanding, the stream resets rather than
    /// deriving a delta from an unACKed frame.
    pub fn push(
        &mut self,
        identity: &FrameIdentity,
        frame: RgbaFrame,
    ) -> Result<FramePacket, FrameDeltaError> {
        identity.validate()?;
        self.check_principal(identity)?;

        if identity != &self.identity {
            let reason = self.identity.change_reason(identity);
            return self.emit_reset(identity.clone(), reason);
        }
        if self.outstanding.is_some() {
            return self.emit_reset(self.identity.clone(), ResetReason::UnacknowledgedFrame);
        }
        // An over-budget input is refused before it enters any retained stream
        // state. The caller may select a separately bounded FULL/no-cache path.
        if frame.byte_len() > self.config.max_cached_bytes {
            return Err(FrameDeltaError::FrameExceedsCacheLimit);
        }
        if let Some(base) = self.acknowledged.as_ref() {
            if base.frame.width != frame.width || base.frame.height != frame.height {
                return self.emit_reset(self.identity.clone(), ResetReason::DimensionsChanged);
            }
        }

        let comparison_started = Instant::now();
        let unchanged = self
            .acknowledged
            .as_ref()
            .is_some_and(|base| base.frame.pixels == frame.pixels);
        let mut compare_micros = elapsed_micros(comparison_started);

        let hash_started = Instant::now();
        let pixel_sha256 = frame.pixel_sha256();
        let mut hash_micros = elapsed_micros(hash_started);

        // Keep the canonical full PNG available to the caller for evidence in
        // every actual-capture mode. The transport must omit it on DELTA and
        // NO_CHANGE; it is not counted as mode-selected wire payload there.
        let encode_started = Instant::now();
        let full_png = encode_png(&frame)?;
        let full_png_encode_micros = elapsed_micros(encode_started);
        let png_hash_started = Instant::now();
        let full_png_sha256 = sha256_hex(&full_png);
        hash_micros = hash_micros.saturating_add(elapsed_micros(png_hash_started));
        let mut timings = FrameTimings {
            compare_micros,
            hash_micros,
            full_png_encode_micros,
            patch_png_encode_micros: 0,
        };

        if unchanged {
            return self.emit_no_change(
                frame.width,
                frame.height,
                full_png,
                pixel_sha256,
                full_png_sha256,
                timings,
            );
        }
        if self.acknowledged.is_none() {
            return self.emit_full_with_hashes(
                frame,
                full_png,
                pixel_sha256,
                full_png_sha256,
                timings,
            );
        }

        // If retaining old and new decoded pixels would exceed the configured
        // cache, forget the old base and use a self-contained FULL packet.
        let combined_cache = self
            .acknowledged
            .as_ref()
            .map_or(0, |base| base.frame.byte_len())
            .checked_add(frame.byte_len())
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        if combined_cache > self.config.max_cached_bytes {
            self.acknowledged = None;
            return self.emit_full_with_hashes(
                frame,
                full_png,
                pixel_sha256,
                full_png_sha256,
                timings,
            );
        }

        let base = self
            .acknowledged
            .as_ref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let compare_started = Instant::now();
        let rectangles = changed_rectangles(&base.frame, &frame, self.config.max_rectangles);
        compare_micros = compare_micros.saturating_add(elapsed_micros(compare_started));
        timings.compare_micros = compare_micros;

        let Some(rectangles) = rectangles else {
            return self.emit_full_with_hashes(
                frame,
                full_png,
                pixel_sha256,
                full_png_sha256,
                timings,
            );
        };

        let mut patches = Vec::new();
        patches
            .try_reserve_exact(rectangles.len())
            .map_err(|_| FrameDeltaError::FrameTooLarge)?;
        let mut delta_estimate = DELTA_METADATA_ESTIMATE_BYTES;
        let mut patch_png_bytes = 0usize;
        for rect in rectangles {
            let patch_started = Instant::now();
            let patch_frame = crop_frame(&frame, rect)?;
            let patch_png = match encode_png(&patch_frame) {
                Ok(bytes) => bytes,
                Err(FrameDeltaError::PngPayloadTooLarge) => {
                    timings.patch_png_encode_micros = timings
                        .patch_png_encode_micros
                        .saturating_add(elapsed_micros(patch_started));
                    return self.emit_full_with_hashes(
                        frame,
                        full_png,
                        pixel_sha256,
                        full_png_sha256,
                        timings,
                    );
                }
                Err(error) => return Err(error),
            };
            timings.patch_png_encode_micros = timings
                .patch_png_encode_micros
                .saturating_add(elapsed_micros(patch_started));
            patch_png_bytes = patch_png_bytes
                .checked_add(patch_png.len())
                .ok_or(FrameDeltaError::FrameTooLarge)?;
            if patch_png_bytes > FRAME_DELTA_MAX_FRAME_BYTES {
                return self.emit_full_with_hashes(
                    frame,
                    full_png,
                    pixel_sha256,
                    full_png_sha256,
                    timings,
                );
            }
            delta_estimate = delta_estimate
                .checked_add(
                    base64_encoded_len(patch_png.len()).ok_or(FrameDeltaError::FrameTooLarge)?,
                )
                .and_then(|sum| sum.checked_add(RECT_METADATA_ESTIMATE_BYTES))
                .ok_or(FrameDeltaError::FrameTooLarge)?;
            let patch_hash_started = Instant::now();
            let patch_png_sha256 = sha256_hex(&patch_png);
            let patch_pixel_sha256 = patch_frame.pixel_sha256();
            timings.hash_micros = timings
                .hash_micros
                .saturating_add(elapsed_micros(patch_hash_started));
            patches.push(FramePatch {
                rect,
                png_sha256: patch_png_sha256,
                pixel_sha256: patch_pixel_sha256,
                png_bytes: patch_png,
            });
        }

        let full_estimate = base64_encoded_len(full_png.len())
            .ok_or(FrameDeltaError::FrameTooLarge)?
            .checked_add(FULL_METADATA_ESTIMATE_BYTES)
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        if delta_estimate >= full_estimate {
            self.emit_full_with_hashes(frame, full_png, pixel_sha256, full_png_sha256, timings)
        } else {
            self.emit_delta(
                frame,
                patches,
                pixel_sha256,
                full_png_sha256,
                full_png,
                timings,
            )
        }
    }

    /// Accept only an explicit ACK for the currently outstanding ID and the
    /// SHA-256 of its complete decoded RGBA8 image.
    pub fn acknowledge(
        &mut self,
        frame_id: u64,
        pixel_sha256: &str,
    ) -> Result<(), FrameDeltaError> {
        let outstanding = self
            .outstanding
            .as_ref()
            .ok_or(FrameDeltaError::UnexpectedAcknowledgement)?;
        if outstanding.id != frame_id {
            return Err(FrameDeltaError::UnexpectedAcknowledgement);
        }
        if outstanding.pixel_sha256 != pixel_sha256 {
            return Err(FrameDeltaError::AcknowledgementHashMismatch);
        }

        let accepted = self
            .outstanding
            .take()
            .ok_or(FrameDeltaError::UnexpectedAcknowledgement)?;
        if let Some(frame) = accepted.frame {
            self.acknowledged = Some(StoredFrame {
                id: accepted.id,
                frame,
                pixel_sha256: accepted.pixel_sha256,
                png_sha256: accepted.png_sha256,
            });
        } else if let Some(base) = self.acknowledged.as_mut() {
            // NO_CHANGE advances the logical base ID but not its image bytes.
            base.id = accepted.id;
            base.pixel_sha256 = accepted.pixel_sha256;
            base.png_sha256 = accepted.png_sha256;
        } else {
            return Err(FrameDeltaError::MissingBaseFrame);
        }
        Ok(())
    }

    /// Drop all cached frame pixels while preserving sequence monotonicity.
    pub fn cleanup(&mut self) {
        self.acknowledged = None;
        self.outstanding = None;
    }

    /// Explicitly invalidate client context. The receiver must apply this reset
    /// before accepting the next FULL packet.
    pub fn require_reset(&mut self) -> Result<FramePacket, FrameDeltaError> {
        self.emit_reset(self.identity.clone(), ResetReason::ClientContextLost)
    }

    fn check_principal(&self, identity: &FrameIdentity) -> Result<(), FrameDeltaError> {
        if identity.owner != self.identity.owner {
            return Err(FrameDeltaError::ForeignOwner);
        }
        if identity.session_id != self.identity.session_id {
            return Err(FrameDeltaError::ForeignSession);
        }
        Ok(())
    }

    fn allocate_id(&mut self) -> Result<u64, FrameDeltaError> {
        let id = self.next_frame_id;
        self.next_frame_id = id
            .checked_add(1)
            .ok_or(FrameDeltaError::SequenceExhausted)?;
        Ok(id)
    }

    fn emit_reset(
        &mut self,
        identity: FrameIdentity,
        reason: ResetReason,
    ) -> Result<FramePacket, FrameDeltaError> {
        self.check_principal(&identity)?;
        let frame_id = self.allocate_id()?;
        self.identity = identity.clone();
        self.acknowledged = None;
        self.outstanding = None;
        Ok(FramePacket {
            frame_id,
            mode: FrameMode::ResetRequired,
            identity,
            width: 0,
            height: 0,
            pixel_format: PixelFormat::Rgba8,
            coordinate_space: CoordinateSpace::CapturePixel,
            base_frame_id: None,
            base_pixel_sha256: None,
            pixel_sha256: String::new(),
            png_sha256: String::new(),
            full_png: Vec::new(),
            patches: Vec::new(),
            reset_reason: Some(reason),
            timings: FrameTimings::default(),
        })
    }

    fn emit_full_with_hashes(
        &mut self,
        frame: RgbaFrame,
        png_bytes: Vec<u8>,
        pixel_sha256: String,
        png_sha256: String,
        timings: FrameTimings,
    ) -> Result<FramePacket, FrameDeltaError> {
        let frame_id = self.allocate_id()?;
        let packet = FramePacket {
            frame_id,
            mode: FrameMode::Full,
            identity: self.identity.clone(),
            width: frame.width,
            height: frame.height,
            pixel_format: PixelFormat::Rgba8,
            coordinate_space: CoordinateSpace::CapturePixel,
            base_frame_id: None,
            base_pixel_sha256: None,
            pixel_sha256: pixel_sha256.clone(),
            png_sha256: png_sha256.clone(),
            full_png: png_bytes,
            patches: Vec::new(),
            reset_reason: None,
            timings,
        };
        self.outstanding = Some(OutstandingFrame {
            id: frame_id,
            pixel_sha256,
            png_sha256,
            frame: Some(frame),
        });
        Ok(packet)
    }

    fn emit_delta(
        &mut self,
        frame: RgbaFrame,
        patches: Vec<FramePatch>,
        pixel_sha256: String,
        png_sha256: String,
        full_png: Vec<u8>,
        timings: FrameTimings,
    ) -> Result<FramePacket, FrameDeltaError> {
        let base = self
            .acknowledged
            .as_ref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let base_frame_id = base.id;
        let base_pixel_sha256 = base.pixel_sha256.clone();
        let frame_id = self.allocate_id()?;
        let packet = FramePacket {
            frame_id,
            mode: FrameMode::Delta,
            identity: self.identity.clone(),
            width: frame.width,
            height: frame.height,
            pixel_format: PixelFormat::Rgba8,
            coordinate_space: CoordinateSpace::CapturePixel,
            base_frame_id: Some(base_frame_id),
            base_pixel_sha256: Some(base_pixel_sha256),
            pixel_sha256: pixel_sha256.clone(),
            png_sha256: png_sha256.clone(),
            full_png,
            patches,
            reset_reason: None,
            timings,
        };
        self.outstanding = Some(OutstandingFrame {
            id: frame_id,
            pixel_sha256,
            png_sha256,
            frame: Some(frame),
        });
        Ok(packet)
    }

    fn emit_no_change(
        &mut self,
        width: u32,
        height: u32,
        full_png: Vec<u8>,
        pixel_sha256: String,
        png_sha256: String,
        timings: FrameTimings,
    ) -> Result<FramePacket, FrameDeltaError> {
        let base = self
            .acknowledged
            .as_ref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let base_id = base.id;
        let frame_id = self.allocate_id()?;
        let packet = FramePacket {
            frame_id,
            mode: FrameMode::NoChange,
            identity: self.identity.clone(),
            width,
            height,
            pixel_format: PixelFormat::Rgba8,
            coordinate_space: CoordinateSpace::CapturePixel,
            base_frame_id: Some(base_id),
            base_pixel_sha256: Some(pixel_sha256.clone()),
            pixel_sha256: pixel_sha256.clone(),
            png_sha256: png_sha256.clone(),
            full_png,
            patches: Vec::new(),
            reset_reason: None,
            timings,
        };
        self.outstanding = Some(OutstandingFrame {
            id: frame_id,
            pixel_sha256,
            png_sha256,
            frame: None,
        });
        Ok(packet)
    }
}

/// Independent client-side reconstruction and protocol validation.
pub struct FrameReconstructor {
    identity: FrameIdentity,
    last_frame_id: Option<u64>,
    frame: Option<RgbaFrame>,
    pixel_sha256: Option<String>,
    png_sha256: Option<String>,
}

impl FrameReconstructor {
    pub fn new(identity: FrameIdentity) -> Result<Self, FrameDeltaError> {
        identity.validate()?;
        Ok(Self {
            identity,
            last_frame_id: None,
            frame: None,
            pixel_sha256: None,
            png_sha256: None,
        })
    }

    pub fn current(&self) -> Option<&RgbaFrame> {
        self.frame.as_ref()
    }

    pub fn current_frame_id(&self) -> Option<u64> {
        self.last_frame_id
    }

    pub fn identity(&self) -> &FrameIdentity {
        &self.identity
    }

    /// Apply a packet atomically. FULL/DELTA/NO_CHANGE return an ACK; a reset
    /// clears the local base and returns `None` because no image was installed.
    pub fn apply(&mut self, packet: &FramePacket) -> Result<Option<FrameAck>, FrameDeltaError> {
        packet.identity.validate()?;
        self.check_principal(&packet.identity)?;
        if packet.mode == FrameMode::ResetRequired {
            self.check_reset_id(packet.frame_id)?;
        } else {
            self.check_next_id(packet.frame_id)?;
        }
        if packet.pixel_format != PixelFormat::Rgba8
            || packet.coordinate_space != CoordinateSpace::CapturePixel
        {
            return Err(FrameDeltaError::InvalidPacket);
        }

        if packet.mode == FrameMode::ResetRequired {
            if packet.width != 0
                || packet.height != 0
                || packet.base_frame_id.is_some()
                || packet.base_pixel_sha256.is_some()
                || !packet.pixel_sha256.is_empty()
                || !packet.png_sha256.is_empty()
                || !packet.full_png.is_empty()
                || !packet.patches.is_empty()
                || packet.reset_reason.is_none()
            {
                return Err(FrameDeltaError::InvalidPacket);
            }
            self.identity = packet.identity.clone();
            self.frame = None;
            self.pixel_sha256 = None;
            self.png_sha256 = None;
            self.last_frame_id = Some(packet.frame_id);
            return Ok(None);
        }

        if packet.identity != self.identity {
            return Err(FrameDeltaError::IdentityMismatch);
        }
        if packet.reset_reason.is_some() {
            return Err(FrameDeltaError::InvalidPacket);
        }

        let reconstruction_started = Instant::now();
        let result = match packet.mode {
            FrameMode::Full => self.apply_full(packet),
            FrameMode::Delta => self.apply_delta(packet),
            FrameMode::NoChange => self.apply_no_change(packet),
            FrameMode::ResetRequired => Err(FrameDeltaError::InvalidPacket),
        };
        match result {
            Ok(Some(mut ack)) => {
                ack.reconstruction_micros = elapsed_micros(reconstruction_started);
                Ok(Some(ack))
            }
            other => other,
        }
    }

    fn apply_full(&mut self, packet: &FramePacket) -> Result<Option<FrameAck>, FrameDeltaError> {
        if packet.base_frame_id.is_some()
            || packet.base_pixel_sha256.is_some()
            || !packet.patches.is_empty()
        {
            return Err(FrameDeltaError::InvalidPacket);
        }
        let png_bytes = &packet.full_png;
        if png_bytes.is_empty() {
            return Err(FrameDeltaError::InvalidPacket);
        }
        if png_bytes.len() > FRAME_DELTA_MAX_FRAME_BYTES {
            return Err(FrameDeltaError::PngPayloadTooLarge);
        }
        if sha256_hex(png_bytes) != packet.png_sha256 {
            return Err(FrameDeltaError::PngHashMismatch);
        }
        let frame = decode_png(png_bytes)?;
        if frame.width != packet.width || frame.height != packet.height {
            return Err(FrameDeltaError::InvalidPacket);
        }
        let pixel_sha256 = frame.pixel_sha256();
        if pixel_sha256 != packet.pixel_sha256 {
            return Err(FrameDeltaError::PixelHashMismatch);
        }
        self.install(
            packet.frame_id,
            frame,
            pixel_sha256,
            packet.png_sha256.clone(),
        );
        Ok(self.make_ack())
    }

    fn apply_delta(&mut self, packet: &FramePacket) -> Result<Option<FrameAck>, FrameDeltaError> {
        if packet.patches.is_empty() || packet.patches.len() > FRAME_DELTA_MAX_RECTANGLES {
            return Err(FrameDeltaError::InvalidPacket);
        }
        let base_id = packet
            .base_frame_id
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let base_hash = packet
            .base_pixel_sha256
            .as_deref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let current = self
            .frame
            .as_ref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        if Some(base_id) != self.last_frame_id {
            return Err(FrameDeltaError::WrongBaseFrame);
        }
        if self.pixel_sha256.as_deref() != Some(base_hash) {
            return Err(FrameDeltaError::WrongBaseHash);
        }
        if packet.width != current.width || packet.height != current.height {
            return Err(FrameDeltaError::WrongBaseDimensions);
        }
        let patch_bytes = packet.patches.iter().try_fold(0usize, |sum, patch| {
            sum.checked_add(patch.png_bytes.len())
                .ok_or(FrameDeltaError::PngPayloadTooLarge)
        })?;
        if patch_bytes > FRAME_DELTA_MAX_FRAME_BYTES {
            return Err(FrameDeltaError::PngPayloadTooLarge);
        }

        let mut reconstructed = current.clone();
        for (index, patch) in packet.patches.iter().enumerate() {
            validate_rect(patch.rect, packet.width, packet.height)?;
            for previous in packet.patches.iter().take(index) {
                if rectangles_overlap(previous.rect, patch.rect)? {
                    return Err(FrameDeltaError::OverlappingPatches);
                }
            }
            if sha256_hex(&patch.png_bytes) != patch.png_sha256 {
                return Err(FrameDeltaError::PngHashMismatch);
            }
            let patch_frame = decode_png(&patch.png_bytes)?;
            if patch_frame.width != patch.rect.width || patch_frame.height != patch.rect.height {
                return Err(FrameDeltaError::WrongPatchDimensions);
            }
            if patch_frame.pixel_sha256() != patch.pixel_sha256 {
                return Err(FrameDeltaError::PatchPixelHashMismatch);
            }
            blit_patch(&mut reconstructed, patch.rect, &patch_frame)?;
        }

        let pixel_sha256 = reconstructed.pixel_sha256();
        if pixel_sha256 != packet.pixel_sha256 {
            return Err(FrameDeltaError::PixelHashMismatch);
        }
        let canonical_png = encode_png(&reconstructed)?;
        if sha256_hex(&canonical_png) != packet.png_sha256 {
            return Err(FrameDeltaError::PngHashMismatch);
        }
        self.install(
            packet.frame_id,
            reconstructed,
            pixel_sha256,
            packet.png_sha256.clone(),
        );
        Ok(self.make_ack())
    }

    fn apply_no_change(
        &mut self,
        packet: &FramePacket,
    ) -> Result<Option<FrameAck>, FrameDeltaError> {
        if !packet.patches.is_empty() {
            return Err(FrameDeltaError::InvalidPacket);
        }
        let base_id = packet
            .base_frame_id
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let base_hash = packet
            .base_pixel_sha256
            .as_deref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        let current = self
            .frame
            .as_ref()
            .ok_or(FrameDeltaError::MissingBaseFrame)?;
        if Some(base_id) != self.last_frame_id {
            return Err(FrameDeltaError::WrongBaseFrame);
        }
        if self.pixel_sha256.as_deref() != Some(base_hash)
            || self.pixel_sha256.as_deref() != Some(packet.pixel_sha256.as_str())
        {
            return Err(FrameDeltaError::WrongBaseHash);
        }
        if packet.width != current.width || packet.height != current.height {
            return Err(FrameDeltaError::WrongBaseDimensions);
        }
        if self.png_sha256.as_deref() != Some(packet.png_sha256.as_str()) {
            return Err(FrameDeltaError::PngHashMismatch);
        }
        self.last_frame_id = Some(packet.frame_id);
        Ok(self.make_ack())
    }

    fn check_principal(&self, identity: &FrameIdentity) -> Result<(), FrameDeltaError> {
        if identity.owner != self.identity.owner {
            return Err(FrameDeltaError::ForeignOwner);
        }
        if identity.session_id != self.identity.session_id {
            return Err(FrameDeltaError::ForeignSession);
        }
        Ok(())
    }

    fn check_next_id(&self, frame_id: u64) -> Result<(), FrameDeltaError> {
        let expected = match self.last_frame_id {
            Some(previous) => previous
                .checked_add(1)
                .ok_or(FrameDeltaError::SequenceExhausted)?,
            None => 1,
        };
        if frame_id != expected {
            return Err(FrameDeltaError::OutOfOrderFrame);
        }
        Ok(())
    }

    fn check_reset_id(&self, frame_id: u64) -> Result<(), FrameDeltaError> {
        // A reset is the recovery path for a dropped/unACKed packet, so it may
        // skip IDs. It must still be strictly newer than any packet already
        // installed; ordinary frames remain contiguous after this reset.
        if frame_id == 0 || self.last_frame_id.is_some_and(|last| frame_id <= last) {
            return Err(FrameDeltaError::OutOfOrderFrame);
        }
        Ok(())
    }

    fn install(
        &mut self,
        frame_id: u64,
        frame: RgbaFrame,
        pixel_sha256: String,
        png_sha256: String,
    ) {
        self.last_frame_id = Some(frame_id);
        self.frame = Some(frame);
        self.pixel_sha256 = Some(pixel_sha256);
        self.png_sha256 = Some(png_sha256);
    }

    fn make_ack(&self) -> Option<FrameAck> {
        Some(FrameAck {
            frame_id: self.last_frame_id?,
            pixel_sha256: self.pixel_sha256.clone()?,
            reconstruction_micros: 0,
        })
    }
}

fn rgba_byte_len(width: u32, height: u32) -> Result<usize, FrameDeltaError> {
    if width == 0 || height == 0 {
        return Err(FrameDeltaError::InvalidDimensions);
    }
    let bytes = usize::try_from(width)
        .ok()
        .and_then(|w| usize::try_from(height).ok().and_then(|h| w.checked_mul(h)))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(FrameDeltaError::FrameTooLarge)?;
    if bytes > FRAME_DELTA_MAX_FRAME_BYTES {
        return Err(FrameDeltaError::FrameTooLarge);
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

fn base64_encoded_len(length: usize) -> Option<usize> {
    length.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

struct BoundedPngWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    limit: usize,
    limit_hit: Arc<AtomicBool>,
}

impl Write for BoundedPngWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Ok(mut bytes) = self.bytes.try_lock() else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "PNG output lock unavailable",
            ));
        };
        let Some(new_len) = bytes.len().checked_add(input.len()) else {
            self.limit_hit.store(true, Ordering::Relaxed);
            return Err(io::Error::new(io::ErrorKind::Other, "PNG size overflow"));
        };
        if new_len > self.limit {
            self.limit_hit.store(true, Ordering::Relaxed);
            return Err(io::Error::new(io::ErrorKind::Other, "PNG size limit"));
        }
        bytes
            .try_reserve(input.len())
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_png(frame: &RgbaFrame) -> Result<Vec<u8>, FrameDeltaError> {
    let limit_hit = Arc::new(AtomicBool::new(false));
    let output = Arc::new(Mutex::new(Vec::new()));
    let sink = BoundedPngWriter {
        bytes: Arc::clone(&output),
        limit: FRAME_DELTA_MAX_FRAME_BYTES,
        limit_hit: Arc::clone(&limit_hit),
    };
    let mut encoder = png::Encoder::new(sink, frame.width, frame.height);
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(BitDepth::Eight);
    let mut writer = match encoder.write_header() {
        Ok(writer) => writer,
        Err(error) => return Err(png_encode_error(error.to_string(), &limit_hit)),
    };
    if let Err(error) = writer.write_image_data(&frame.pixels) {
        return Err(png_encode_error(error.to_string(), &limit_hit));
    }
    match writer.finish() {
        Ok(()) => {}
        Err(error) => return Err(png_encode_error(error.to_string(), &limit_hit)),
    }
    Arc::try_unwrap(output)
        .map_err(|_| FrameDeltaError::PngEncodeFailed("PNG output still shared".into()))?
        .into_inner()
        .map_err(|_| FrameDeltaError::PngEncodeFailed("PNG output mutex poisoned".into()))
}

fn png_encode_error(message: String, limit_hit: &AtomicBool) -> FrameDeltaError {
    if limit_hit.load(Ordering::Relaxed) {
        FrameDeltaError::PngPayloadTooLarge
    } else {
        FrameDeltaError::PngEncodeFailed(message)
    }
}

fn decode_png(bytes: &[u8]) -> Result<RgbaFrame, FrameDeltaError> {
    if bytes.len() > FRAME_DELTA_MAX_FRAME_BYTES {
        return Err(FrameDeltaError::PngPayloadTooLarge);
    }
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_limits(png::Limits {
        bytes: FRAME_DELTA_MAX_FRAME_BYTES,
    });
    let mut reader = decoder
        .read_info()
        .map_err(|error| FrameDeltaError::PngDecodeFailed(error.to_string()))?;
    if reader.info().color_type != ColorType::Rgba || reader.info().bit_depth != BitDepth::Eight {
        return Err(FrameDeltaError::InvalidPngFormat);
    }
    let width = reader.info().width;
    let height = reader.info().height;
    let expected = rgba_byte_len(width, height)?;
    let output_size = reader
        .output_buffer_size()
        .ok_or(FrameDeltaError::FrameTooLarge)?;
    if output_size < expected || output_size > FRAME_DELTA_MAX_FRAME_BYTES {
        return Err(FrameDeltaError::FrameTooLarge);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| FrameDeltaError::FrameTooLarge)?;
    output.resize(output_size, 0);
    let info = reader
        .next_frame(&mut output)
        .map_err(|error| FrameDeltaError::PngDecodeFailed(error.to_string()))?;
    if info.width != width
        || info.height != height
        || info.color_type != ColorType::Rgba
        || info.bit_depth != BitDepth::Eight
        || info.buffer_size() < expected
    {
        return Err(FrameDeltaError::InvalidPngFormat);
    }
    output.truncate(expected);
    RgbaFrame::new(width, height, output)
}

fn changed_rectangles(
    base: &RgbaFrame,
    current: &RgbaFrame,
    max_rectangles: usize,
) -> Option<Vec<FrameRect>> {
    if base.width != current.width || base.height != current.height {
        return None;
    }
    let block = usize::try_from(FRAME_DELTA_BLOCK_SIZE).ok()?;
    let width = usize::try_from(current.width).ok()?;
    let height = usize::try_from(current.height).ok()?;
    let columns = width.checked_add(block - 1)? / block;
    let rows = height.checked_add(block - 1)? / block;
    let tile_count = columns.checked_mul(rows)?;
    let mut changed = Vec::new();
    changed.try_reserve_exact(tile_count).ok()?;
    changed.resize(tile_count, 0u8);

    for row in 0..rows {
        for column in 0..columns {
            if tile_differs(base, current, column, row, block)? {
                changed[row * columns + column] = 1;
            }
        }
    }

    let mut visited = Vec::new();
    visited.try_reserve_exact(tile_count).ok()?;
    visited.resize(tile_count, 0u8);
    let mut queue = Vec::new();
    queue.try_reserve_exact(tile_count).ok()?;
    let mut rectangles = Vec::new();
    rectangles.try_reserve_exact(max_rectangles).ok()?;

    for first in 0..tile_count {
        if changed[first] == 0 || visited[first] != 0 {
            continue;
        }
        queue.clear();
        queue.push(first);
        visited[first] = 1;
        let mut head = 0usize;
        let first_row = first / columns;
        let first_column = first % columns;
        let (mut min_x, mut max_x) = (first_column, first_column);
        let (mut min_y, mut max_y) = (first_row, first_row);

        while head < queue.len() {
            let at = queue[head];
            head += 1;
            let row = at / columns;
            let column = at % columns;
            min_x = min_x.min(column);
            max_x = max_x.max(column);
            min_y = min_y.min(row);
            max_y = max_y.max(row);
            let neighbors = [
                (column.checked_sub(1), Some(row)),
                (
                    column.checked_add(1).filter(|next| *next < columns),
                    Some(row),
                ),
                (Some(column), row.checked_sub(1)),
                (Some(column), row.checked_add(1).filter(|next| *next < rows)),
            ];
            for (next_x, next_y) in neighbors {
                let (Some(next_x), Some(next_y)) = (next_x, next_y) else {
                    continue;
                };
                let next = next_y * columns + next_x;
                if changed[next] != 0 && visited[next] == 0 {
                    visited[next] = 1;
                    queue.push(next);
                }
            }
        }

        if rectangles.len() == max_rectangles {
            return None;
        }
        let x = u32::try_from(min_x.checked_mul(block)?).ok()?;
        let y = u32::try_from(min_y.checked_mul(block)?).ok()?;
        let right = u32::try_from(max_x.checked_add(1)?.checked_mul(block)?)
            .ok()?
            .min(current.width);
        let bottom = u32::try_from(max_y.checked_add(1)?.checked_mul(block)?)
            .ok()?
            .min(current.height);
        rectangles.push(FrameRect {
            x,
            y,
            width: right.checked_sub(x)?,
            height: bottom.checked_sub(y)?,
        });
    }
    for (index, rect) in rectangles.iter().enumerate() {
        for previous in rectangles.iter().take(index) {
            if rectangles_overlap(*previous, *rect).ok()? {
                // Disconnected changed-tile components can have overlapping
                // bounding boxes (for example, a ring around an island). Such
                // regions are ambiguous as independent patches, so use FULL.
                return None;
            }
        }
    }
    Some(rectangles)
}

fn tile_differs(
    base: &RgbaFrame,
    current: &RgbaFrame,
    column: usize,
    row: usize,
    block: usize,
) -> Option<bool> {
    let width = usize::try_from(current.width).ok()?;
    let height = usize::try_from(current.height).ok()?;
    let left = column.checked_mul(block)?;
    let top = row.checked_mul(block)?;
    let right = left.checked_add(block)?.min(width);
    let bottom = top.checked_add(block)?.min(height);
    for y in top..bottom {
        let start = y.checked_mul(width)?.checked_add(left)?.checked_mul(4)?;
        let end = y.checked_mul(width)?.checked_add(right)?.checked_mul(4)?;
        if base.pixels.get(start..end)? != current.pixels.get(start..end)? {
            return Some(true);
        }
    }
    Some(false)
}

fn crop_frame(frame: &RgbaFrame, rect: FrameRect) -> Result<RgbaFrame, FrameDeltaError> {
    validate_rect(rect, frame.width, frame.height)?;
    let byte_len = rgba_byte_len(rect.width, rect.height)?;
    let width = usize::try_from(frame.width).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let x = usize::try_from(rect.x).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let y = usize::try_from(rect.y).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let patch_width = usize::try_from(rect.width).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let patch_height = usize::try_from(rect.height).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let row_bytes = patch_width
        .checked_mul(4)
        .ok_or(FrameDeltaError::FrameTooLarge)?;
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(byte_len)
        .map_err(|_| FrameDeltaError::FrameTooLarge)?;
    for offset_y in 0..patch_height {
        let start = y
            .checked_add(offset_y)
            .and_then(|line| line.checked_mul(width))
            .and_then(|line| line.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(4))
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        let end = start
            .checked_add(row_bytes)
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        pixels.extend_from_slice(
            frame
                .pixels
                .get(start..end)
                .ok_or(FrameDeltaError::InvalidPacket)?,
        );
    }
    RgbaFrame::new(rect.width, rect.height, pixels)
}

fn validate_rect(rect: FrameRect, width: u32, height: u32) -> Result<(), FrameDeltaError> {
    if rect.width == 0 || rect.height == 0 {
        return Err(FrameDeltaError::PatchOutOfBounds);
    }
    let right = rect
        .x
        .checked_add(rect.width)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    let bottom = rect
        .y
        .checked_add(rect.height)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    if right > width || bottom > height {
        return Err(FrameDeltaError::PatchOutOfBounds);
    }
    Ok(())
}

fn rectangles_overlap(left: FrameRect, right: FrameRect) -> Result<bool, FrameDeltaError> {
    let left_right = left
        .x
        .checked_add(left.width)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    let left_bottom = left
        .y
        .checked_add(left.height)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    let right_right = right
        .x
        .checked_add(right.width)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    let right_bottom = right
        .y
        .checked_add(right.height)
        .ok_or(FrameDeltaError::PatchOutOfBounds)?;
    Ok(left.x < right_right
        && right.x < left_right
        && left.y < right_bottom
        && right.y < left_bottom)
}

fn blit_patch(
    frame: &mut RgbaFrame,
    rect: FrameRect,
    patch: &RgbaFrame,
) -> Result<(), FrameDeltaError> {
    validate_rect(rect, frame.width, frame.height)?;
    if patch.width != rect.width || patch.height != rect.height {
        return Err(FrameDeltaError::WrongPatchDimensions);
    }
    let frame_width = usize::try_from(frame.width).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let x = usize::try_from(rect.x).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let y = usize::try_from(rect.y).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let patch_width = usize::try_from(rect.width).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let patch_height = usize::try_from(rect.height).map_err(|_| FrameDeltaError::FrameTooLarge)?;
    let row_bytes = patch_width
        .checked_mul(4)
        .ok_or(FrameDeltaError::FrameTooLarge)?;
    for offset_y in 0..patch_height {
        let target_start = y
            .checked_add(offset_y)
            .and_then(|line| line.checked_mul(frame_width))
            .and_then(|line| line.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(4))
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        let target_end = target_start
            .checked_add(row_bytes)
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        let source_start = offset_y
            .checked_mul(patch_width)
            .and_then(|pixel| pixel.checked_mul(4))
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        let source_end = source_start
            .checked_add(row_bytes)
            .ok_or(FrameDeltaError::FrameTooLarge)?;
        let source = patch
            .pixels
            .get(source_start..source_end)
            .ok_or(FrameDeltaError::InvalidPacket)?;
        let target = frame
            .pixels
            .get_mut(target_start..target_end)
            .ok_or(FrameDeltaError::PatchOutOfBounds)?;
        target.copy_from_slice(source);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(owner: &str, session: &str) -> FrameIdentity {
        FrameIdentity {
            owner: owner.into(),
            session_id: session.into(),
            window_id: "window-1".into(),
            capture_id: "capture-1".into(),
            process_id: 41,
            process_birth: 9001,
            geometry_generation: 7,
        }
    }

    fn noisy_frame(width: u32, height: u32, seed: u32) -> RgbaFrame {
        let size = rgba_byte_len(width, height).expect("small test dimensions");
        let mut pixels = Vec::with_capacity(size);
        let mut state = seed;
        for _ in 0..(size / 4) {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pixels.push((state >> 24) as u8);
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pixels.push((state >> 24) as u8);
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pixels.push((state >> 24) as u8);
            pixels.push(255);
        }
        RgbaFrame::new(width, height, pixels).expect("valid test pixels")
    }

    fn edit_pixels(frame: &RgbaFrame, points: &[(u32, u32)]) -> RgbaFrame {
        let mut pixels = frame.pixels.clone();
        for (x, y) in points {
            let at = ((*y as usize * frame.width as usize) + *x as usize) * 4;
            pixels[at] ^= 0x5a;
            pixels[at + 1] ^= 0xa5;
        }
        RgbaFrame::new(frame.width, frame.height, pixels).expect("valid edited frame")
    }

    fn base_and_delta() -> (FrameIdentity, FramePacket, FramePacket) {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let base = noisy_frame(192, 128, 5);
        let full = stream.push(&identity, base.clone()).expect("full");
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        let ack = receiver
            .apply(&full)
            .expect("apply full")
            .expect("full ack");
        stream
            .acknowledge(ack.frame_id, &ack.pixel_sha256)
            .expect("ack full");
        let changed = edit_pixels(&base, &[(4, 4), (140, 90)]);
        let delta = stream.push(&identity, changed).expect("delta or full");
        assert_eq!(delta.mode, FrameMode::Delta);
        (identity, full, delta)
    }

    #[test]
    fn full_delta_no_change_reconstructs_exact_rgba_and_acks_each_sequence() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let first_pixels = noisy_frame(192, 128, 13);
        let first = stream
            .push(&identity, first_pixels.clone())
            .expect("first full");
        assert_eq!(first.mode, FrameMode::Full);
        assert!(!first.full_png.is_empty());
        assert_eq!(first.pixel_sha256, first_pixels.pixel_sha256());
        assert_eq!(first.png_sha256, sha256_hex(&first.full_png));
        assert_ne!(first.pixel_sha256, first.png_sha256);

        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        let ack = receiver.apply(&first).expect("apply full").expect("ACK");
        stream
            .acknowledge(ack.frame_id, &ack.pixel_sha256)
            .expect("ACK full");

        let second_pixels = edit_pixels(&first_pixels, &[(4, 4), (140, 90)]);
        let second = stream
            .push(&identity, second_pixels.clone())
            .expect("delta");
        assert_eq!(second.mode, FrameMode::Delta);
        assert_eq!(second.base_frame_id, Some(first.frame_id));
        assert_eq!(
            second.patches.len(),
            2,
            "independent changed blocks stay separate"
        );
        assert_eq!(second.png_sha256, sha256_hex(&second.full_png));
        for patch in &second.patches {
            assert_eq!(patch.png_sha256, sha256_hex(&patch.png_bytes));
        }
        assert!(second.incremental_image_bytes() < second.full_only_image_bytes());
        assert!(matches!(second.wire_payload(), FrameWirePayload::Delta(_)));
        let ack = receiver.apply(&second).expect("apply delta").expect("ACK");
        assert_eq!(receiver.current(), Some(&second_pixels));
        stream
            .acknowledge(ack.frame_id, &ack.pixel_sha256)
            .expect("ACK delta");

        let unchanged = stream
            .push(&identity, second_pixels.clone())
            .expect("no change");
        assert_eq!(unchanged.mode, FrameMode::NoChange);
        assert!(
            !unchanged.full_png.is_empty(),
            "full evidence remains available"
        );
        assert!(unchanged.patches.is_empty());
        assert_eq!(unchanged.incremental_image_bytes(), 0);
        assert!(unchanged.full_only_image_bytes() > 0);
        assert_eq!(unchanged.base_frame_id, Some(second.frame_id));
        let ack = receiver
            .apply(&unchanged)
            .expect("apply no change")
            .expect("ACK");
        stream
            .acknowledge(ack.frame_id, &ack.pixel_sha256)
            .expect("ACK no change");
        assert_eq!(receiver.current(), Some(&second_pixels));
        assert_eq!(stream.cached_bytes(), second_pixels.pixels.len());
    }

    #[test]
    fn no_unacknowledged_frame_can_become_a_delta_base() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let pixels = noisy_frame(96, 96, 2);
        let first = stream.push(&identity, pixels.clone()).expect("first full");
        let reset = stream
            .push(&identity, edit_pixels(&pixels, &[(2, 2)]))
            .expect("unACKed reset");
        assert_eq!(first.mode, FrameMode::Full);
        assert_eq!(reset.mode, FrameMode::ResetRequired);
        assert_eq!(reset.reset_reason, Some(ResetReason::UnacknowledgedFrame));
        assert_eq!(stream.cached_bytes(), 0);
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        assert_eq!(
            receiver.apply(&reset).expect("recover from lost frame"),
            None
        );
        let full = stream.push(&identity, pixels).expect("new full");
        assert_eq!(full.mode, FrameMode::Full);
        assert_eq!(full.frame_id, reset.frame_id + 1);
        assert_eq!(
            receiver
                .apply(&full)
                .expect("apply recovery full")
                .expect("ACK")
                .frame_id,
            full.frame_id
        );
    }

    #[test]
    fn identity_and_geometry_changes_reset_before_emitting_pixels() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let pixels = noisy_frame(80, 80, 4);
        let first = stream.push(&identity, pixels.clone()).expect("full");
        stream
            .acknowledge(first.frame_id, &first.pixel_sha256)
            .expect("ACK");

        let mut moved = identity.clone();
        moved.geometry_generation += 1;
        let reset = stream
            .push(&moved, edit_pixels(&pixels, &[(1, 1)]))
            .expect("geometry reset");
        assert_eq!(reset.mode, FrameMode::ResetRequired);
        assert_eq!(reset.reset_reason, Some(ResetReason::GeometryChanged));
        assert_eq!(reset.identity, moved);
        let full = stream.push(&moved, pixels).expect("fresh full");
        assert_eq!(full.mode, FrameMode::Full);
    }

    #[test]
    fn window_capture_and_process_birth_changes_are_identity_resets() {
        let original = identity("owner-a", "session-a");
        for mutate in 0..3 {
            let mut stream = FrameDeltaStream::new(original.clone()).expect("stream");
            let full = stream
                .push(&original, noisy_frame(32, 32, 100 + mutate))
                .expect("full");
            stream
                .acknowledge(full.frame_id, &full.pixel_sha256)
                .expect("ACK");
            let mut changed = original.clone();
            match mutate {
                0 => changed.window_id = "window-2".into(),
                1 => changed.capture_id = "capture-2".into(),
                _ => changed.process_birth += 1,
            }
            let reset = stream
                .push(&changed, noisy_frame(32, 32, 200 + mutate))
                .expect("identity reset");
            assert_eq!(reset.mode, FrameMode::ResetRequired);
            assert_eq!(reset.reset_reason, Some(ResetReason::IdentityChanged));
            assert_eq!(reset.identity, changed);
        }
    }

    #[test]
    fn foreign_owner_or_session_is_rejected_without_cross_client_state() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let pixels = noisy_frame(32, 32, 8);
        let first = stream.push(&identity, pixels.clone()).expect("full");
        stream
            .acknowledge(first.frame_id, &first.pixel_sha256)
            .expect("ACK");

        let mut foreign = identity.clone();
        foreign.owner = "owner-b".into();
        foreign.session_id = "session-b".into();
        assert_eq!(
            stream.push(&foreign, pixels.clone()).unwrap_err(),
            FrameDeltaError::ForeignOwner
        );
        let mut other_session = identity.clone();
        other_session.session_id = "session-b".into();
        assert_eq!(
            stream.push(&other_session, pixels.clone()).unwrap_err(),
            FrameDeltaError::ForeignSession
        );
        assert_eq!(stream.identity(), &identity);

        let mut other_stream = FrameDeltaStream::new(foreign.clone()).expect("other stream");
        let other_full = other_stream
            .push(&foreign, pixels.clone())
            .expect("isolated full");
        assert_eq!(other_full.mode, FrameMode::Full);
        assert_ne!(other_full.identity.session_id, identity.session_id);
    }

    #[test]
    fn wrong_ack_id_or_hash_is_rejected_and_cache_is_bounded() {
        let identity = identity("owner-a", "session-a");
        let config = FrameDeltaConfig {
            max_rectangles: 4,
            max_cached_bytes: 256,
        };
        let mut stream =
            FrameDeltaStream::with_config(identity.clone(), config).expect("bounded stream");
        let frame = RgbaFrame::new(8, 8, vec![7; 8 * 8 * 4]).expect("frame");
        let full = stream.push(&identity, frame).expect("full");
        assert!(stream.cached_bytes() <= config.max_cached_bytes);
        assert_eq!(
            stream
                .acknowledge(full.frame_id + 1, &full.pixel_sha256)
                .unwrap_err(),
            FrameDeltaError::UnexpectedAcknowledgement
        );
        assert_eq!(
            stream.acknowledge(full.frame_id, "00").unwrap_err(),
            FrameDeltaError::AcknowledgementHashMismatch
        );
        stream
            .acknowledge(full.frame_id, &full.pixel_sha256)
            .expect("valid ACK");

        let too_large_for_cache =
            RgbaFrame::new(9, 8, vec![8; 9 * 8 * 4]).expect("frame within protocol cap");
        assert_eq!(
            stream.push(&identity, too_large_for_cache).unwrap_err(),
            FrameDeltaError::FrameExceedsCacheLimit
        );
        stream.cleanup();
        assert_eq!(stream.cached_bytes(), 0);
    }

    #[test]
    fn default_eight_mib_cache_holds_two_950_by_700_rgba_frames() {
        let identity = identity("owner-a", "session-a");
        let config = FrameDeltaConfig::default();
        assert_eq!(config.max_cached_bytes, 8 * 1024 * 1024);
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let base = RgbaFrame::new(950, 700, vec![0; 950usize * 700 * 4]).expect("base");
        let full = stream.push(&identity, base.clone()).expect("full");
        stream
            .acknowledge(full.frame_id, &full.pixel_sha256)
            .expect("ACK");
        let changed = edit_pixels(&base, &[(300, 400)]);
        let packet = stream.push(&identity, changed).expect("second frame");
        assert!(matches!(packet.mode, FrameMode::Delta | FrameMode::Full));
        assert_eq!(stream.cached_bytes(), 2 * 950 * 700 * 4);
        assert!(stream.cached_bytes() <= config.max_cached_bytes);
    }

    #[test]
    fn resize_requires_reset_then_a_new_full_frame() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let first = stream
            .push(&identity, noisy_frame(64, 64, 1))
            .expect("full");
        stream
            .acknowledge(first.frame_id, &first.pixel_sha256)
            .expect("ACK");
        let resized = stream
            .push(&identity, noisy_frame(128, 64, 2))
            .expect("resize reset");
        assert_eq!(resized.mode, FrameMode::ResetRequired);
        assert_eq!(resized.reset_reason, Some(ResetReason::DimensionsChanged));
        let full = stream
            .push(&identity, noisy_frame(128, 64, 2))
            .expect("new full");
        assert_eq!(full.mode, FrameMode::Full);
    }

    #[test]
    fn rectangle_limit_and_wire_cost_fall_back_to_full() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::with_config(
            identity.clone(),
            FrameDeltaConfig {
                max_rectangles: 1,
                max_cached_bytes: FRAME_DELTA_MAX_FRAME_BYTES,
            },
        )
        .expect("stream");
        let base = noisy_frame(192, 128, 22);
        let full = stream.push(&identity, base.clone()).expect("full");
        stream
            .acknowledge(full.frame_id, &full.pixel_sha256)
            .expect("ACK");
        let changed = edit_pixels(&base, &[(4, 4), (140, 90)]);
        let packet = stream.push(&identity, changed).expect("bounded fallback");
        assert_eq!(packet.mode, FrameMode::Full);
        assert!(!packet.full_png.is_empty());
    }

    #[test]
    fn delta_wire_estimate_at_or_above_full_selects_full() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let base = RgbaFrame::new(32, 32, vec![0; 32 * 32 * 4]).expect("base");
        let full = stream.push(&identity, base.clone()).expect("full");
        stream
            .acknowledge(full.frame_id, &full.pixel_sha256)
            .expect("ACK");
        let changed = edit_pixels(&base, &[(3, 4)]);
        let packet = stream.push(&identity, changed).expect("wire fallback");
        assert_eq!(packet.mode, FrameMode::Full);
        assert!(!packet.full_png.is_empty());
    }

    #[test]
    fn overlapping_component_bounds_fall_back_to_full() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let base = RgbaFrame::new(192, 192, vec![0; 192 * 192 * 4]).expect("base");
        let full = stream.push(&identity, base.clone()).expect("full");
        stream
            .acknowledge(full.frame_id, &full.pixel_sha256)
            .expect("ACK");

        // A changed 3x3 ring and its changed center are distinct 4-connected
        // components, but their bounding boxes overlap.
        let changed = edit_pixels(
            &base,
            &[
                (10, 10),
                (70, 10),
                (130, 10),
                (10, 70),
                (130, 70),
                (10, 130),
                (70, 130),
                (130, 130),
                (70, 70),
            ],
        );
        let packet = stream.push(&identity, changed).expect("bounded fallback");
        assert_eq!(packet.mode, FrameMode::Full);
    }

    #[test]
    fn base64_wire_length_estimate_is_overflow_checked() {
        assert_eq!(base64_encoded_len(0), Some(0));
        assert_eq!(base64_encoded_len(1), Some(4));
        assert_eq!(base64_encoded_len(3), Some(4));
        assert_eq!(base64_encoded_len(4), Some(8));
        assert_eq!(base64_encoded_len(usize::MAX), None);
    }

    #[test]
    fn per_stream_state_is_send_safe_for_http_worker_ownership() {
        fn assert_send<T: Send>() {}
        assert_send::<FrameDeltaStream>();
        assert_send::<FrameReconstructor>();
    }

    #[test]
    fn receiver_rejects_wrong_owner_base_order_and_corrupt_patch() {
        let (identity, full, delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");

        let mut foreign = delta.clone();
        foreign.identity.owner = "foreign-owner".into();
        assert_eq!(
            receiver.apply(&foreign).unwrap_err(),
            FrameDeltaError::ForeignOwner
        );

        let mut foreign_session = delta.clone();
        foreign_session.identity.session_id = "foreign-session".into();
        assert_eq!(
            receiver.apply(&foreign_session).unwrap_err(),
            FrameDeltaError::ForeignSession
        );

        let (_, full, mut delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        delta.base_frame_id = Some(999);
        assert_eq!(
            receiver.apply(&delta).unwrap_err(),
            FrameDeltaError::WrongBaseFrame
        );

        let (_, full, mut delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        delta.base_pixel_sha256 = Some("f".repeat(64));
        assert_eq!(
            receiver.apply(&delta).unwrap_err(),
            FrameDeltaError::WrongBaseHash
        );

        let (_, full, mut delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        delta.frame_id += 1;
        assert_eq!(
            receiver.apply(&delta).unwrap_err(),
            FrameDeltaError::OutOfOrderFrame
        );

        let (_, full, mut delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity).expect("receiver");
        receiver.apply(&full).expect("apply base");
        delta.patches[0].png_bytes[0] ^= 0xff;
        assert!(receiver.apply(&delta).is_err());
    }

    #[test]
    fn receiver_rejects_patch_dimensions_outside_overlap_and_resize_without_reset() {
        let (identity, full, mut wrong_dimensions) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        wrong_dimensions.patches[0].rect.width += 1;
        assert_eq!(
            receiver.apply(&wrong_dimensions).unwrap_err(),
            FrameDeltaError::WrongPatchDimensions
        );

        let (_, full, mut outside) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        outside.patches[0].rect.x = outside.width;
        assert_eq!(
            receiver.apply(&outside).unwrap_err(),
            FrameDeltaError::PatchOutOfBounds
        );

        let (_, full, mut overlap) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        receiver.apply(&full).expect("apply base");
        overlap.patches[1].rect = overlap.patches[0].rect;
        assert_eq!(
            receiver.apply(&overlap).unwrap_err(),
            FrameDeltaError::OverlappingPatches
        );

        let (_, full, mut resized_delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity).expect("receiver");
        receiver.apply(&full).expect("apply base");
        resized_delta.width += 1;
        assert_eq!(
            receiver.apply(&resized_delta).unwrap_err(),
            FrameDeltaError::WrongBaseDimensions
        );
    }

    #[test]
    fn duplicate_delta_and_missing_base_are_rejected() {
        let (identity, full, delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity).expect("receiver");
        receiver.apply(&full).expect("apply base");
        receiver.apply(&delta).expect("apply delta");
        assert_eq!(
            receiver.apply(&delta).unwrap_err(),
            FrameDeltaError::OutOfOrderFrame
        );

        let (identity, _, mut delta) = base_and_delta();
        let mut receiver = FrameReconstructor::new(identity).expect("empty receiver");
        delta.frame_id = 1;
        assert_eq!(
            receiver.apply(&delta).unwrap_err(),
            FrameDeltaError::MissingBaseFrame
        );
    }

    #[test]
    fn explicit_reset_is_sequenced_and_clears_receiver_context() {
        let identity = identity("owner-a", "session-a");
        let mut stream = FrameDeltaStream::new(identity.clone()).expect("stream");
        let mut receiver = FrameReconstructor::new(identity.clone()).expect("receiver");
        let full = stream
            .push(&identity, noisy_frame(64, 64, 3))
            .expect("full");
        let ack = receiver.apply(&full).expect("apply").expect("ACK");
        stream
            .acknowledge(ack.frame_id, &ack.pixel_sha256)
            .expect("ACK");
        let reset = stream.require_reset().expect("reset");
        assert_eq!(receiver.apply(&reset).expect("apply reset"), None);
        assert!(receiver.current().is_none());
        let next = stream
            .push(&identity, noisy_frame(64, 64, 3))
            .expect("new full");
        assert_eq!(next.mode, FrameMode::Full);
        assert_eq!(next.frame_id, reset.frame_id + 1);
        assert_eq!(
            receiver
                .apply(&next)
                .expect("apply new full")
                .expect("ACK")
                .frame_id,
            next.frame_id
        );
    }
}

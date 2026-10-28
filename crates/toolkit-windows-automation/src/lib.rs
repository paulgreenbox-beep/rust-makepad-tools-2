mod accessibility;
mod contract;
mod capture_geometry;
pub mod frame_delta;
pub mod desktop_arbiter;
#[cfg(windows)]
pub mod owned_process;
mod evidence;
mod identity;
mod mcp;
#[cfg(windows)]
mod request_control;
mod platform;
mod tool_registry;

/// Trusted App Remote backend; MCP routing requires a pinned operator config.
#[cfg(feature = "experimental-makepad-remote")]
pub mod makepad_remote;

pub use accessibility::*;
pub use contract::*;
pub use capture_geometry::CaptureGeometry;
pub use evidence::{EvidenceEntry, EvidenceLog, now_unix_ms};
pub use mcp::run_mcp_stdio;
#[cfg(windows)]
pub use mcp::http::run_mcp_http;
pub use platform::WindowsAutomation;
#[cfg(windows)]
pub use platform::{
    AccessibilityAction, AccessibilityActionHandler, AccessibilityActionRequest,
    AccessibilityActionTicket, CheckedAccessibilityActionHandler,
    DesktopInputReservation, PhysicalPixelScope, WindowsAccessibilityBridge,
};
pub use tool_registry::{GuiToolRegistry, ToolCallEnvelope, ToolDefinition};

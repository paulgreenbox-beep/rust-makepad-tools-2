#[cfg(windows)]
mod accessibility_windows;
#[cfg(not(windows))]
mod stub;
#[cfg(windows)]
mod windows_backend;

#[cfg(windows)]
pub use accessibility_windows::{
    AccessibilityAction, AccessibilityActionHandler, AccessibilityActionRequest,
    AccessibilityActionTicket, CheckedAccessibilityActionHandler,
    WindowsAccessibilityBridge,
};
#[cfg(not(windows))]
pub use stub::WindowsAutomation;
#[cfg(windows)]
pub use windows_backend::DesktopInputReservation;
#[cfg(windows)]
pub use windows_backend::PhysicalPixelScope;
#[cfg(windows)]
pub use windows_backend::WindowsAutomation;

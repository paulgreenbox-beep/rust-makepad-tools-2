//! ABI projections for nullable UIA out parameters in windows-rs 0.61.
//!
//! The generated high-level Rust traits return non-null interfaces. The Windows
//! contracts allow S_OK + NULL. These private, IID/layout-identical projections
//! use raw out parameters; every object and action still belongs to Provider.
//! No null Rust Interface value is ever constructed.
#![allow(non_snake_case)]
use super::*;
use windows::Win32::UI::Accessibility::UIA_PATTERN_ID;
use windows_core::IUnknown_Vtbl;

#[windows_core::interface("d6dd68d1-86fd-4332-8666-9abedea2d24c")]
pub unsafe trait AbiSimple: IUnknown {
    unsafe fn ProviderOptions(&self, out: *mut ProviderOptions) -> HRESULT;
    unsafe fn GetPatternProvider(&self, id: UIA_PATTERN_ID, out: *mut *mut c_void) -> HRESULT;
    unsafe fn GetPropertyValue(
        &self,
        id: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID,
        out: *mut VARIANT,
    ) -> HRESULT;
    unsafe fn HostRawElementProvider(&self, out: *mut *mut c_void) -> HRESULT;
}

#[windows_core::interface("f7063da8-8359-439c-9297-bbc5299a7d87")]
pub unsafe trait AbiFragment: IUnknown {
    unsafe fn Navigate(&self, direction: NavigateDirection, out: *mut *mut c_void) -> HRESULT;
    unsafe fn GetRuntimeId(&self, out: *mut *mut SAFEARRAY) -> HRESULT;
    unsafe fn BoundingRectangle(&self, out: *mut UiaRect) -> HRESULT;
    unsafe fn GetEmbeddedFragmentRoots(&self, out: *mut *mut SAFEARRAY) -> HRESULT;
    unsafe fn SetFocus(&self) -> HRESULT;
    unsafe fn FragmentRoot(&self, out: *mut *mut c_void) -> HRESULT;
}

#[windows_core::interface("620ce2a5-ab8f-40a9-86cb-de3c75599b58")]
pub unsafe trait AbiRoot: IUnknown {
    unsafe fn ElementProviderFromPoint(&self, x: f64, y: f64, out: *mut *mut c_void) -> HRESULT;
    unsafe fn GetFocus(&self, out: *mut *mut c_void) -> HRESULT;
}

const E_POINTER: HRESULT = HRESULT(0x80004003u32 as i32);

unsafe fn scalar<T: Default>(out: *mut T, result: WinResult<T>) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    // COM callers pass uninitialised output memory, never a live Rust value.
    unsafe {
        out.write(T::default());
    }
    match result {
        Ok(value) => {
            unsafe {
                out.write(value);
            }
            HRESULT(0)
        }
        Err(error) => error.code(),
    }
}

unsafe fn interface<T: Interface>(out: *mut *mut c_void, result: WinResult<Option<T>>) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe {
        out.write(std::ptr::null_mut());
    }
    match result {
        Ok(Some(value)) => {
            unsafe {
                out.write(value.into_raw());
            }
            HRESULT(0)
        }
        Ok(None) => HRESULT(0),
        Err(error) => error.code(),
    }
}

impl AbiSimple_Impl for Provider_Impl {
    unsafe fn ProviderOptions(&self, out: *mut ProviderOptions) -> HRESULT {
        unsafe { scalar(out, IRawElementProviderSimple_Impl::ProviderOptions(self)) }
    }
    unsafe fn GetPatternProvider(&self, id: UIA_PATTERN_ID, out: *mut *mut c_void) -> HRESULT {
        let result = match IRawElementProviderSimple_Impl::GetPatternProvider(self, id) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.code() == UIA_E_NOTSUPPORTED => Ok(None),
            Err(error) => Err(error),
        };
        unsafe { interface(out, result) }
    }
    unsafe fn GetPropertyValue(
        &self,
        id: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID,
        out: *mut VARIANT,
    ) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        unsafe {
            scalar(
                out,
                IRawElementProviderSimple_Impl::GetPropertyValue(self, id),
            )
        }
    }
    unsafe fn HostRawElementProvider(&self, out: *mut *mut c_void) -> HRESULT {
        let result = self.node().and_then(|_| {
            if self.is_root() {
                unsafe { UiaHostProviderFromHwnd(hwnd_from_value(self.state.hwnd_value)) }.map(Some)
            } else {
                Ok(None)
            }
        });
        unsafe { interface(out, result) }
    }
}

impl AbiFragment_Impl for Provider_Impl {
    unsafe fn Navigate(&self, direction: NavigateDirection, out: *mut *mut c_void) -> HRESULT {
        unsafe { interface(out, self.navigate_optional(direction)) }
    }
    unsafe fn GetRuntimeId(&self, out: *mut *mut SAFEARRAY) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        unsafe { scalar(out, IRawElementProviderFragment_Impl::GetRuntimeId(self)) }
    }
    unsafe fn BoundingRectangle(&self, out: *mut UiaRect) -> HRESULT {
        unsafe {
            scalar(
                out,
                IRawElementProviderFragment_Impl::BoundingRectangle(self),
            )
        }
    }
    unsafe fn GetEmbeddedFragmentRoots(&self, out: *mut *mut SAFEARRAY) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        unsafe {
            scalar(
                out,
                IRawElementProviderFragment_Impl::GetEmbeddedFragmentRoots(self),
            )
        }
    }
    unsafe fn SetFocus(&self) -> HRESULT {
        IRawElementProviderFragment_Impl::SetFocus(self).map_or_else(|e| e.code(), |_| HRESULT(0))
    }
    unsafe fn FragmentRoot(&self, out: *mut *mut c_void) -> HRESULT {
        unsafe {
            interface(
                out,
                IRawElementProviderFragment_Impl::FragmentRoot(self).map(Some),
            )
        }
    }
}

impl AbiRoot_Impl for Provider_Impl {
    unsafe fn ElementProviderFromPoint(&self, x: f64, y: f64, out: *mut *mut c_void) -> HRESULT {
        unsafe { interface(out, self.point_optional(x, y)) }
    }
    unsafe fn GetFocus(&self, out: *mut *mut c_void) -> HRESULT {
        unsafe { interface(out, self.focus_optional()) }
    }
}

macro_rules! canonical_projection {
    ($canonical:ty,$abi:ty) => {
        impl From<Provider> for $canonical {
            fn from(value: Provider) -> Self {
                let abi: $abi = value.into();
                // Same IID, IUnknown base and complete method order/signatures.
                // Transfer its non-null owned COM reference without refcount loss.
                unsafe { Self::from_raw(abi.into_raw()) }
            }
        }
    };
}
canonical_projection!(IRawElementProviderSimple, AbiSimple);
canonical_projection!(IRawElementProviderFragment, AbiFragment);
canonical_projection!(IRawElementProviderFragmentRoot, AbiRoot);

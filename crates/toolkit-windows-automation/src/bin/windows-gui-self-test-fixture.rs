#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
fn main() {
    eprintln!("windows-gui-self-test-fixture is available only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> windows::core::Result<()> {
    fixture::run()
}

#[cfg(windows)]
mod fixture {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{COLOR_WINDOW, HBRUSH, UpdateWindow};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        BS_AUTORADIOBUTTON, BS_PUSHBUTTON, CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW,
        DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, GetClientRect,
        GetMessageW, HMENU, IDC_ARROW, LoadCursorW, MSG, MoveWindow, PostQuitMessage,
        RegisterClassW, SW_SHOW, SetWindowTextW, ShowWindow, TranslateMessage, WINDOW_EX_STYLE,
        WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SIZE, WNDCLASSW, WS_CAPTION, WS_CHILD,
        WS_EX_CLIENTEDGE, WS_GROUP, WS_MINIMIZEBOX, WS_OVERLAPPEDWINDOW, WS_SYSMENU, WS_TABSTOP,
        WS_VISIBLE,
    };
    use windows::core::{PCWSTR, w};

    const ID_INCREMENT: usize = 101;
    const ID_DUPLICATE_A: usize = 102;
    const ID_DUPLICATE_B: usize = 103;
    const ID_REMOVE_TRANSIENT: usize = 104;
    const ID_EXIT: usize = 105;
    const ID_EDIT: usize = 106;
    const ID_STATUS: usize = 107;
    const ID_TRANSIENT: usize = 108;
    const ID_CHOICE_A: usize = 109;
    const ID_CHOICE_B: usize = 110;

    static STATUS: AtomicIsize = AtomicIsize::new(0);
    static EDIT: AtomicIsize = AtomicIsize::new(0);
    static INCREMENT: AtomicIsize = AtomicIsize::new(0);
    static DUPLICATE_A: AtomicIsize = AtomicIsize::new(0);
    static DUPLICATE_B: AtomicIsize = AtomicIsize::new(0);
    static REMOVE_TRANSIENT: AtomicIsize = AtomicIsize::new(0);
    static EXIT: AtomicIsize = AtomicIsize::new(0);
    static TRANSIENT: AtomicIsize = AtomicIsize::new(0);
    static CHOICE_A: AtomicIsize = AtomicIsize::new(0);
    static CHOICE_B: AtomicIsize = AtomicIsize::new(0);
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static VALUE_DELAY_MS: AtomicUsize = AtomicUsize::new(0);

    pub fn run() -> windows::core::Result<()> {
        // Fixed operator-only cancellation fixture seam. Default behavior is
        // unchanged. A real EN_CHANGE witnesses dispatch before bounded delay.
        if let Some(value) = std::env::args().skip_while(|a| a != "--value-delay-ms").nth(1) {
            let delay: usize = value.parse().expect("bounded integer delay required");
            assert!((1..=2000).contains(&delay), "fixture delay must be 1..2000ms");
            VALUE_DELAY_MS.store(delay, Ordering::SeqCst);
        }
        let title = std::env::args()
            .skip_while(|argument| argument != "--title")
            .nth(1)
            .unwrap_or_else(|| "Toolkit Windows GUI Self-Test Fixture".to_owned());
        let fixed_size = std::env::args().any(|argument| argument == "--fixed-size");
        let title = wide(&title);
        unsafe {
            let module = GetModuleHandleW(None)?;
            let instance = HINSTANCE(module.0);
            let class_name = w!("ToolkitWindowsGuiSelfTestFixture");
            let class = WNDCLASSW {
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hInstance: instance,
                lpszClassName: class_name,
                hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as isize as *mut c_void),
                lpfnWndProc: Some(window_proc),
                ..Default::default()
            };
            if RegisterClassW(&class) == 0 {
                return Err(windows::core::Error::from_win32());
            }
            let window = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                PCWSTR(title.as_ptr()),
                if fixed_size {
                    WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE
                } else {
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE
                },
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                760,
                560,
                None,
                None,
                Some(instance),
                None,
            )?;
            let _ = ShowWindow(window, SW_SHOW);
            let _ = UpdateWindow(window);

            let mut message = MSG::default();
            while GetMessageW(&mut message, None, 0, 0).0 > 0 {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    unsafe extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_CREATE => {
                let _create = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
                if let Err(error) = unsafe { create_controls(window) } {
                    eprintln!("fixture control creation failed: {error}");
                    return LRESULT(-1);
                }
                unsafe { layout_controls(window) };
                LRESULT(0)
            }
            WM_SIZE => {
                unsafe { layout_controls(window) };
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = wparam.0 & 0xffff;
                match id {
                    ID_EDIT if (wparam.0 >> 16) & 0xffff == 0x0300 => {
                        let delay = VALUE_DELAY_MS.load(Ordering::SeqCst);
                        if delay > 0 {
                            use std::io::Write;
                            println!("{{\"fixture_event\":\"VALUE_CHANGED_DISPATCHED\",\"pid\":{},\"delay_ms\":{delay}}}", std::process::id());
                            let _ = std::io::stdout().flush();
                            std::thread::sleep(std::time::Duration::from_millis(delay as u64));
                        }
                    }
                    ID_INCREMENT => {
                        let count = COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                        let text = wide(&format!("Count: {count}"));
                        let status = hwnd_from_atomic(&STATUS);
                        if !status.0.is_null() {
                            let _ = unsafe { SetWindowTextW(status, PCWSTR(text.as_ptr())) };
                        }
                    }
                    ID_REMOVE_TRANSIENT => {
                        let transient = hwnd_from_atomic(&TRANSIENT);
                        if !transient.0.is_null() {
                            let _ = unsafe { DestroyWindow(transient) };
                            TRANSIENT.store(0, Ordering::SeqCst);
                        }
                    }
                    ID_EXIT => {
                        let _ = unsafe { DestroyWindow(window) };
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                unsafe { PostQuitMessage(0) };
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
        }
    }

    unsafe fn create_controls(parent: HWND) -> windows::core::Result<()> {
        INCREMENT.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Increment",
                    ID_INCREMENT,
                    button_style(),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        DUPLICATE_A.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Duplicate",
                    ID_DUPLICATE_A,
                    button_style(),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        DUPLICATE_B.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Duplicate",
                    ID_DUPLICATE_B,
                    button_style(),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        REMOVE_TRANSIENT.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Remove transient",
                    ID_REMOVE_TRANSIENT,
                    button_style(),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        EXIT.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Exit fixture",
                    ID_EXIT,
                    button_style(),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        EDIT.store(
            unsafe {
                child(
                    parent,
                    w!("EDIT"),
                    "",
                    ID_EDIT,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(ES_AUTOHSCROLL as u32),
                    WS_EX_CLIENTEDGE,
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        STATUS.store(
            unsafe {
                child(
                    parent,
                    w!("STATIC"),
                    "Count: 0",
                    ID_STATUS,
                    WS_CHILD | WS_VISIBLE,
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        TRANSIENT.store(
            unsafe {
                child(
                    parent,
                    w!("STATIC"),
                    "Transient control",
                    ID_TRANSIENT,
                    WS_CHILD | WS_VISIBLE,
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        CHOICE_A.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Choice A",
                    ID_CHOICE_A,
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_TABSTOP
                        | WS_GROUP
                        | WINDOW_STYLE(BS_AUTORADIOBUTTON as u32),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        CHOICE_B.store(
            unsafe {
                child(
                    parent,
                    w!("BUTTON"),
                    "Choice B",
                    ID_CHOICE_B,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTORADIOBUTTON as u32),
                    WINDOW_EX_STYLE::default(),
                )?
            }
            .0 as isize,
            Ordering::SeqCst,
        );
        Ok(())
    }

    unsafe fn child(
        parent: HWND,
        class: PCWSTR,
        text: &str,
        id: usize,
        style: WINDOW_STYLE,
        extended_style: WINDOW_EX_STYLE,
    ) -> windows::core::Result<HWND> {
        let text = wide(text);
        unsafe {
            CreateWindowExW(
                extended_style,
                class,
                PCWSTR(text.as_ptr()),
                style,
                0,
                0,
                100,
                28,
                Some(parent),
                Some(HMENU(id as *mut c_void)),
                None,
                None,
            )
        }
    }

    unsafe fn layout_controls(window: HWND) {
        let mut client = RECT::default();
        if unsafe { GetClientRect(window, &mut client) }.is_err() {
            return;
        }
        let width = (client.right - client.left).max(320);
        let content_width = (width - 40).max(280);
        move_control(&INCREMENT, 20, 20, 130, 34);
        move_control(&DUPLICATE_A, 160, 20, 130, 34);
        if width < 700 {
            move_control(&DUPLICATE_B, 20, 66, 130, 34);
            move_control(&REMOVE_TRANSIENT, 160, 66, 180, 34);
        } else {
            move_control(&DUPLICATE_B, 300, 20, 130, 34);
            move_control(&REMOVE_TRANSIENT, 20, 66, 180, 34);
        }
        move_control(&EXIT, (width - 150).max(220), 20, 130, 34);
        move_control(&STATUS, 20, 118, content_width, 26);
        move_control(&TRANSIENT, 20, 150, content_width, 26);
        move_control(&EDIT, 20, 196, content_width, 34);
        move_control(&CHOICE_A, 20, 246, 130, 30);
        move_control(&CHOICE_B, 160, 246, 130, 30);
    }

    fn move_control(slot: &AtomicIsize, x: i32, y: i32, width: i32, height: i32) {
        let control = hwnd_from_atomic(slot);
        if !control.0.is_null() {
            let _ = unsafe { MoveWindow(control, x, y, width, height, true) };
        }
    }

    fn hwnd_from_atomic(slot: &AtomicIsize) -> HWND {
        HWND(slot.load(Ordering::SeqCst) as *mut c_void)
    }

    fn button_style() -> WINDOW_STYLE {
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32)
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

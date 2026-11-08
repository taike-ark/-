//! NetRadar 桌面版 — Win32 + GDI+ 液态玻璃界面
#![windows_subsystem = "windows"]

mod anim;
mod gfx;
mod state;
mod theme;
mod ui;

use gfx::Painter;
use std::ffi::c_void;
use state::{App, UiEvent};

type Hwnd = isize;
type Hdc = isize;
type Hinstance = isize;
type Hcursor = isize;

#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: Option<unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize>,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: Hinstance,
    h_icon: isize,
    h_cursor: Hcursor,
    hbr_background: isize,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: isize,
}

#[repr(C)]
struct RectT {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct Msg {
    hwnd: Hwnd,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
    private: u32,
}

#[repr(C)]
struct MinMaxInfo {
    reserved: [i32; 2],
    max_size: [i32; 2],
    max_pos: [i32; 2],
    min_track: [i32; 2],
    max_track: [i32; 2],
}

#[repr(C)]
struct TrackMouse {
    cb_size: u32,
    flags: u32,
    hwnd: Hwnd,
    hover_time: u32,
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WndClassExW) -> u16;
    fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        title: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: Hwnd,
        menu: isize,
        inst: Hinstance,
        param: *mut c_void,
    ) -> Hwnd;
    fn DefWindowProcW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    fn ShowWindow(h: Hwnd, cmd: i32) -> i32;
    fn UpdateWindow(h: Hwnd) -> i32;
    fn GetMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32) -> i32;
    fn TranslateMessage(m: *const Msg) -> i32;
    fn DispatchMessageW(m: *const Msg) -> isize;
    fn PostQuitMessage(code: i32);
    fn InvalidateRect(h: Hwnd, r: *const RectT, erase: i32) -> i32;
    fn ValidateRect(h: Hwnd, r: *const RectT) -> i32;
    fn GetClientRect(h: Hwnd, r: *mut RectT) -> i32;
    fn GetWindowRect(h: Hwnd, r: *mut RectT) -> i32;
    fn SetTimer(h: Hwnd, id: usize, ms: u32, cb: *mut c_void) -> usize;
    fn LoadCursorW(inst: Hinstance, name: *const u16) -> Hcursor;
    fn SetCursor(c: Hcursor) -> Hcursor;
    fn GetSystemMetrics(idx: i32) -> i32;
    fn GetDC(h: Hwnd) -> Hdc;
    fn ReleaseDC(h: Hwnd, dc: Hdc) -> i32;
    fn SendMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    fn ReleaseCapture() -> i32;
    fn TrackMouseEvent(t: *mut TrackMouse) -> i32;
    fn GetKeyState(vk: i32) -> i16;
    fn SetProcessDPIAware() -> i32;
    fn GetDpiForWindow(h: Hwnd) -> u32;
    fn LoadIconW(inst: Hinstance, name: *const u16) -> isize;
    fn IsZoomed(h: Hwnd) -> i32;
    fn DestroyWindow(h: Hwnd) -> i32;
}

#[cfg_attr(target_env = "msvc", link(name = "gdi32"))]
// GNU/gnullvm 下 gdi32/gdiplus/shell32 由 build.rs 以 DLL 形式直链
extern "system" {
    fn CreateCompatibleDC(dc: Hdc) -> Hdc;
    fn CreateCompatibleBitmap(dc: Hdc, w: i32, h: i32) -> isize;
    fn SelectObject(dc: Hdc, obj: isize) -> isize;
    fn DeleteObject(obj: isize) -> i32;
    fn DeleteDC(dc: Hdc) -> i32;
    fn BitBlt(dst: Hdc, x: i32, y: i32, w: i32, h: i32, src: Hdc, sx: i32, sy: i32, rop: u32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn GetTickCount64() -> u64;
    fn GetLastError() -> u32;
    fn LoadLibraryA(name: *const std::os::raw::c_char) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const std::os::raw::c_char) -> *mut c_void;
}

const WS_POPUP: u32 = 0x8000_0000;
const WS_THICKFRAME: u32 = 0x0004_0000;
const WS_MINIMIZEBOX: u32 = 0x0002_0000;
const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const SW_SHOW: i32 = 5;
const SW_MINIMIZE: i32 = 6;
const SW_MAXIMIZE: i32 = 3;
const SW_RESTORE: i32 = 9;

const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_TIMER: u32 = 0x0113;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_MOUSELEAVE: u32 = 0x02A3;
const WM_GETMINMAXINFO: u32 = 0x0024;
const WM_NCHITTEST: u32 = 0x0084;
const WM_SETCURSOR: u32 = 0x0020;
const WM_CHAR: u32 = 0x0102;
const WM_KEYDOWN: u32 = 0x0100;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_DPICHANGED: u32 = 0x02E0;
const WM_LBUTTONDBLCLK: u32 = 0x0203;
const WM_SIZE: u32 = 0x0005;

const HTCLIENT: isize = 1;
const HTCAPTION: isize = 2;
const HTLEFT: isize = 10;
const HTRIGHT: isize = 11;
const HTTOP: isize = 12;
const HTTOPLEFT: isize = 13;
const HTTOPRIGHT: isize = 14;
const HTBOTTOM: isize = 15;
const HTBOTTOMLEFT: isize = 16;
const HTBOTTOMRIGHT: isize = 17;

const VK_RETURN: i32 = 0x0D;
const VK_ESCAPE: i32 = 0x1B;
const VK_BACK: i32 = 0x08;
const VK_CONTROL: i32 = 0x11;

const SRCCOPY: u32 = 0x00CC_0020;

struct Gdi {
    mem: Hdc,
    bmp: isize,
    old: isize,
    w: i32,
    h: i32,
}

static mut APP: *mut App = std::ptr::null_mut();

static mut SCALE: f32 = 1.0;
static mut BACK: Option<Gdi> = None;
static mut BG: Option<Gdi> = None;
static mut HOT_BUTTON: bool = false;
static mut LAST_MOUSE: (i32, i32) = (-1, -1);

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn glog(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("netradar-gui.log"))
    {
        let _ = writeln!(f, "{}", msg);
    }
}

unsafe fn app() -> &'static mut App {
    &mut *APP
}

/// Win11 圆角窗口（失败则忽略）
unsafe fn set_round_corners(hwnd: Hwnd) {
    let dll = LoadLibraryA(b"dwmapi.dll\0".as_ptr() as *const std::os::raw::c_char);
    if dll.is_null() {
        return;
    }
    let f = GetProcAddress(dll, b"DwmSetWindowAttribute\0".as_ptr() as *const std::os::raw::c_char);
    if f.is_null() {
        return;
    }
    let func: unsafe extern "system" fn(Hwnd, u32, *const c_void, u32) -> i32 =
        std::mem::transmute(f);
    let pref: u32 = 2; // DWMWCP_ROUND
    let _ = func(hwnd, 33, &pref as *const u32 as *const c_void, 4);
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        glog(&format!("PANIC: {}", info));
    }));
    unsafe {
        let _gp = gfx::GdiPlus::init();
        let _ = SetProcessDPIAware();
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("NetRadarLiquidClass");
        let title = wide("NetRadar 网络发现器");

        let wc = WndClassExW {
            cb_size: std::mem::size_of::<WndClassExW>() as u32,
            style: 0x0002 | 0x0001,
            lpfn_wnd_proc: Some(wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: instance,
            h_icon: LoadIconW(0, 32512 as *const u16),
            h_cursor: LoadCursorW(0, 32512 as *const u16),
            hbr_background: 0,
            lpsz_menu_name: std::ptr::null(),
            lpsz_class_name: class_name.as_ptr(),
            h_icon_sm: LoadIconW(0, 32512 as *const u16),
        };
        RegisterClassExW(&wc);

        let screen_w = GetSystemMetrics(0);
        let screen_h = GetSystemMetrics(1);
        let w = 1240.min(screen_w - 60);
        let h = 820.min(screen_h - 80);
        let x = (screen_w - w) / 2;
        let y = (screen_h - h) / 2 - 10;

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU,
            x,
            y,
            w,
            h,
            0,
            0,
            instance,
            std::ptr::null_mut(),
        );
        if hwnd == 0 {
            glog(&format!("CreateWindow failed err={}", GetLastError()));
            return;
        }
        set_round_corners(hwnd);

        SCALE = GetDpiForWindow(hwnd) as f32 / 96.0;
        if SCALE <= 0.0 {
            SCALE = 1.0;
        }
        let (tx, rx) = state::make_channels();
        let fonts = theme::Fonts::load();
        APP = Box::into_raw(Box::new(App::new(hwnd, fonts, tx, rx)));

        let mut crc = RectT { left: 0, top: 0, right: 0, bottom: 0 };
        GetClientRect(hwnd, &mut crc);
        glog(&format!("screen={}x{} req={}x{} client={}x{} dpi={}", screen_w, screen_h, w, h, crc.right, crc.bottom, GetDpiForWindow(hwnd)));
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        SetTimer(hwnd, 1, 16, std::ptr::null_mut());

        if std::env::var("NETRADAR_AUTOSCAN").is_ok() {
            app().start_scan();
        }
        if std::env::var("NETRADAR_SIGNALS").is_ok() {
            app().page = state::PAGE_SIGNALS;
            app().page_since = 0;
            app().start_signals();
        }
        { let a = app(); a.tab_anim.from = a.page as f32; a.tab_anim.to = a.page as f32; a.tab_anim.start = 0; a.tab_anim.dur = 1; }
        if let Ok(p) = std::env::var("NETRADAR_PAGE") {
            app().page = match p.as_str() {
                "capture" => state::PAGE_CAPTURE,
                "signals" => state::PAGE_SIGNALS,
                "about" => state::PAGE_ABOUT,
                _ => state::PAGE_SCAN,
            };
            app().tab_anim.to = app().page as f32;
        }
        if std::env::var("NETRADAR_DEMO").is_ok() {
            let demo = [
                ("13:20:41.512", "TCP", "10.191.211.79:52344", "104.18.2.1:443", "52344 → 443 flags=S len=0"),
                ("13:20:41.553", "TCP", "104.18.2.1:443", "10.191.211.79:52344", "443 → 52344 flags=SA len=0"),
                ("13:20:41.561", "UDP", "10.191.211.79:53021", "223.5.5.5:53", "53021 → 53 len=38"),
                ("13:20:41.623", "ICMP", "10.191.211.79", "10.191.211.233", "echo-request"),
                ("13:20:41.702", "ARP", "BE:16:62:32:ED:88", "broadcast", "who-has 10.191.211.233 tell 10.191.211.79"),
                ("13:20:41.884", "TCP", "10.191.211.79:52350", "151.101.1.140:80", "52350 → 80 flags=PA len=412"),
                ("13:20:42.011", "UDP", "10.191.211.79:12345", "239.255.255.250:1900", "12345 → 1900 len=126"),
                ("13:20:42.180", "TCP", "10.191.211.233:25", "10.191.211.79:52360", "25 → 52360 flags=PA len=88"),
            ];
            let a = app();
            for (stamp, proto, src, dst, info) in demo {
                a.packets.push(state::PktLine {
                    stamp: stamp.to_string(),
                    proto: proto.to_string(),
                    src: src.to_string(),
                    dst: dst.to_string(),
                    info: info.to_string(),
                });
            }
            a.cap_packets = 1284;
            a.cap_bytes = 986_432;
            a.cap_tcp = 1024;
            a.cap_udp = 214;
        }

        let mut msg = Msg {
            hwnd: 0,
            message: 0,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt_x: 0,
            pt_y: 0,
            private: 0,
        };
        loop {
            let r = GetMessageW(&mut msg, 0, 0, 0);
            if r <= 0 {
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

unsafe fn ensure_back(hwnd: Hwnd, w: i32, h: i32) {
    let need = match &BACK {
        Some(b) => b.w != w || b.h != h,
        None => true,
    };
    if !need {
        return;
    }
    if let Some(b) = BACK.take() {
        SelectObject(b.mem, b.old);
        DeleteObject(b.bmp);
        DeleteDC(b.mem);
    }
    let screen = GetDC(0);
    let mem = CreateCompatibleDC(screen);
    let bmp = CreateCompatibleBitmap(screen, w.max(1), h.max(1));
    let old = SelectObject(mem, bmp);
    ReleaseDC(0, screen);
    BACK = Some(Gdi { mem, bmp, old, w, h });
    let _ = hwnd;
}

unsafe fn ensure_bg(hwnd: Hwnd, w: i32, h: i32) {
    let need = match &BG {
        Some(b) => b.w != w || b.h != h,
        None => true,
    };
    if !need {
        return;
    }
    if let Some(b) = BG.take() {
        SelectObject(b.mem, b.old);
        DeleteObject(b.bmp);
        DeleteDC(b.mem);
    }
    let screen = GetDC(0);
    let mem = CreateCompatibleDC(screen);
    let bmp = CreateCompatibleBitmap(screen, w.max(1), h.max(1));
    let old = SelectObject(mem, bmp);
    ReleaseDC(0, screen);
    BG = Some(Gdi { mem, bmp, old, w, h });
    if let Some(b) = &BG {
        let painter = Painter::new(b.mem);
        painter.set_scale(SCALE);
        ui::background(&painter, (w as f32 / SCALE) as i32, (h as f32 / SCALE) as i32, 0);
        drop(painter);
    }
    let _ = hwnd;
}

unsafe fn paint(hwnd: Hwnd) {
    let mut rc = RectT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    GetClientRect(hwnd, &mut rc);
    let w = rc.right;
    let h = rc.bottom;
    if w <= 0 || h <= 0 {
        return;
    }
    ensure_back(hwnd, w, h);
    ensure_bg(hwnd, w, h);
    let hdc = GetDC(hwnd);
    if let (Some(b), Some(bg)) = (&BACK, &BG) {
        BitBlt(b.mem, 0, 0, w, h, bg.mem, 0, 0, SRCCOPY);
        let painter = Painter::new(b.mem);
        painter.set_scale(SCALE);
        ui::draw(app(), &painter, (w as f32 / SCALE) as i32, (h as f32 / SCALE) as i32);
        drop(painter);
        BitBlt(hdc, 0, 0, w, h, b.mem, 0, 0, SRCCOPY);
    }
    ReleaseDC(hwnd, hdc);
    ValidateRect(hwnd, std::ptr::null());
}

unsafe fn logical(x: i32, y: i32) -> (i32, i32) {
    ((x as f32 / SCALE) as i32, (y as f32 / SCALE) as i32)
}

unsafe fn hit_test_resize(hwnd: Hwnd, x: i32, y: i32) -> isize {
    let mut rc = RectT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    GetClientRect(hwnd, &mut rc);
    let edge = (6.0 * SCALE) as i32;
    let left = x < edge;
    let right = x >= rc.right - edge;
    let top = y < edge;
    let bottom = y >= rc.bottom - edge;
    match (left, right, top, bottom) {
        (true, _, true, _) => HTTOPLEFT,
        (_, true, true, _) => HTTOPRIGHT,
        (true, _, _, true) => HTBOTTOMLEFT,
        (_, true, _, true) => HTBOTTOMRIGHT,
        (true, _, _, _) => HTLEFT,
        (_, true, _, _) => HTRIGHT,
        (_, _, true, _) => HTTOP,
        (_, _, _, true) => HTBOTTOM,
        _ => HTCLIENT,
    }
}

unsafe fn dispatch_click(app: &mut App, id: u32) {
    match id {
        state::ID_TAB_SCAN => app.change_page(state::PAGE_SCAN),
        state::ID_TAB_CAPTURE => app.change_page(state::PAGE_CAPTURE),
        state::ID_TAB_SIGNALS => {
            app.change_page(state::PAGE_SIGNALS);
            if app.wifi.is_empty() && app.bt.is_empty() && app.wifi_err.is_empty() {
                app.start_signals();
            }
        }
        state::ID_TAB_ABOUT => app.change_page(state::PAGE_ABOUT),
        state::ID_SCAN_START => app.start_scan(),
        state::ID_SCAN_STOP => app.stop_scan(),
        state::ID_CAP_START => app.start_capture(),
        state::ID_CAP_STOP => app.stop_capture(),
        state::ID_CAP_SAVE => app.save_pcap = !app.save_pcap,
        state::ID_FILTER_ALL => app.filter.clear(),
        state::ID_FILTER_TCP => app.filter = "tcp".into(),
        state::ID_FILTER_UDP => app.filter = "udp".into(),
        state::ID_FILTER_ICMP => app.filter = "icmp".into(),
        state::ID_SIG_REFRESH => app.start_signals(),
        state::ID_SIG_LOCATION => netradar_core::signals::open_location_settings(),
        state::ID_EXPORT_HTML => export(app, "html"),
        state::ID_EXPORT_CSV => export(app, "csv"),
        state::ID_EXPORT_JSON => export(app, "json"),
        state::ID_MIN => {
            ShowWindow(app.hwnd, SW_MINIMIZE);
        }
        state::ID_MAX => {
            if IsZoomed(app.hwnd) != 0 {
                ShowWindow(app.hwnd, SW_RESTORE);
            } else {
                ShowWindow(app.hwnd, SW_MAXIMIZE);
            }
        }
        state::ID_CLOSE => {
            DestroyWindow(app.hwnd);
        }
        other if other >= 1000 && other < 2000 => {
            let idx = (other - 1000) as usize;
            app.selected = if app.selected == Some(idx) { None } else { Some(idx) };
        }
        _ => {}
    }
    app.dirty = true;
}

unsafe fn export(app: &mut App, kind: &str) {
    use netradar_core::report;
    use netradar_core::{Host, PortInfo};
    if app.hosts.is_empty() {
        app.set_status("没有可导出的数据", 2);
        return;
    }
    let _ = std::fs::create_dir_all("reports");
    let ts = report::local_datetime()
        .replace('-', "")
        .replace(':', "")
        .replace(' ', "_");
    let hosts: Vec<Host> = app
        .hosts
        .iter()
        .map(|h| {
            let mut host = Host::new(netradar_core::parse_ip(&h.ip).unwrap_or(0));
            host.mac = if h.mac == "-" { None } else { Some(h.mac.clone()) };
            host.vendor = if h.vendor.is_empty() { None } else { Some(h.vendor.clone()) };
            host.hostname = if h.name.is_empty() { None } else { Some(h.name.clone()) };
            host.rtt_ms = if h.rtt >= 0 { Some(h.rtt as u32) } else { None };
            host.ports = h
                .ports
                .iter()
                .filter_map(|p| p.parse::<u16>().ok())
                .map(|p| PortInfo {
                    port: p,
                    service: netradar_core::services::service_name(p),
                    banner: None,
                })
                .collect();
            host
        })
        .collect();
    let meta = report::Meta {
        network: app.cidr.clone(),
        scanned: app.scanned,
        elapsed_ms: app.elapsed_ms,
        iface: app.iface.clone(),
        local_ip: app.my_ip.clone(),
    };
    let (path, content) = match kind {
        "html" => (
            format!("reports/netradar_{}.html", ts),
            report::to_html(&hosts, &meta),
        ),
        "csv" => (format!("reports/netradar_{}.csv", ts), report::to_csv(&hosts)),
        _ => (
            format!("reports/netradar_{}.json", ts),
            report::to_json(&hosts, &meta),
        ),
    };
    match report::write_file(&path, &content) {
        Ok(_) => {
            let abs = std::fs::canonicalize(&path)
                .map(|p| p.to_string_lossy().replace("\\\\?\\", ""))
                .unwrap_or_else(|_| path.clone());
            app.set_status(&format!("已导出 {}", abs), 1);
            app.push_log(format!("导出: {}", abs));
        }
        Err(e) => app.set_status(&e, 3),
    }
}

unsafe extern "system" fn wnd_proc(hwnd: Hwnd, msg: u32, wp: usize, lp: isize) -> isize {
    match msg {
        WM_PAINT => {
            paint(hwnd);
            return 0;
        }
        WM_ERASEBKGND => return 1,
        WM_SIZE => {
            BACK = None;
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_DPICHANGED => {
            BACK = None;
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_GETMINMAXINFO => {
            let mmi = &mut *(lp as *mut MinMaxInfo);
            mmi.min_track = [(900.0 * SCALE) as i32, (620.0 * SCALE) as i32];
            return 0;
        }
        WM_NCHITTEST => {
            let x = (lp & 0xFFFF) as i16 as i32;
            let y = ((lp >> 16) & 0xFFFF) as i16 as i32;
            let mut wr = RectT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            GetWindowRect(hwnd, &mut wr);
            let hit = hit_test_resize(hwnd, x - wr.left, y - wr.top);
            return hit;
        }
        WM_SETCURSOR => {
            let cursor = if HOT_BUTTON {
                state_cursor_hand()
            } else {
                32512 as *const u16
            };
            SetCursor(LoadCursorW(0, cursor));
            return 1;
        }
        WM_MOUSEMOVE => {
            let x = (lp & 0xFFFF) as i16 as i32;
            let y = ((lp >> 16) & 0xFFFF) as i16 as i32;
            let (lx, ly) = logical(x, y);
            let a = app();
            ui::set_mouse(lx, ly);
            let id = a.hit(lx, ly);
            if a.hover != id {
                a.hover = id;
                HOT_BUTTON = id != 0;
                a.dirty = true;
            }
            LAST_MOUSE = (lx, ly);
            let mut tme = TrackMouse {
                cb_size: std::mem::size_of::<TrackMouse>() as u32,
                flags: 0x0000_0002,
                hwnd,
                hover_time: 0,
            };
            TrackMouseEvent(&mut tme);
            return 0;
        }
        WM_MOUSELEAVE => {
            let a = app();
            a.hover = 0;
            HOT_BUTTON = false;
            a.dirty = true;
            LAST_MOUSE = (-1, -1);
            return 0;
        }
        WM_LBUTTONDOWN => {
            let x = (lp & 0xFFFF) as i16 as i32;
            let y = ((lp >> 16) & 0xFFFF) as i16 as i32;
            let (lx, ly) = logical(x, y);
            let a = app();
            let id = a.hit(lx, ly);
            a.pressed = id;
            if id == 0 && ly < ui::HDR_H {
                ReleaseCapture();
                SendMessageW(hwnd, 0x00A1, HTCAPTION as usize, 0);
                return 0;
            }
            a.cidr_focus = id == state::ID_CIDR;
            a.filter_focus = id == state::ID_FILTER;
            a.dirty = true;
            return 0;
        }
        WM_LBUTTONUP => {
            let x = (lp & 0xFFFF) as i16 as i32;
            let y = ((lp >> 16) & 0xFFFF) as i16 as i32;
            let (lx, ly) = logical(x, y);
            let a = app();
            let id = a.hit(lx, ly);
            let pressed = a.pressed;
            a.pressed = 0;
            if pressed != 0 && pressed == id {
                dispatch_click(a, id);
            }
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_LBUTTONDBLCLK => {
            let y = ((lp >> 16) & 0xFFFF) as i16 as i32;
            let (_, ly) = logical(0, y);
            if ly < ui::HDR_H {
                if IsZoomed(hwnd) != 0 {
                    ShowWindow(hwnd, SW_RESTORE);
                } else {
                    ShowWindow(hwnd, SW_MAXIMIZE);
                }
            }
            return 0;
        }
        WM_MOUSEWHEEL => {
            let delta = ((wp >> 16) & 0xFFFF) as i16 as i32;
            let a = app();
            let step = 40;
            match a.page {
                state::PAGE_SCAN => a.scroll = (a.scroll - delta / 120 * step * 3).max(0),
                state::PAGE_CAPTURE => {
                    a.pkt_scroll = (a.pkt_scroll + delta / 120 * 3).clamp(0, 6000)
                }
                state::PAGE_SIGNALS => {
                    a.sig_scroll = (a.sig_scroll + delta / 120 * 3).clamp(0, 400)
                }
                _ => {}
            }
            a.dirty = true;
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_CHAR => {
            let ch = wp as u32;
            let a = app();
            if a.cidr_focus {
                if ch == 8 {
                    a.cidr.pop();
                } else if ch >= 32 && ch < 127 && a.cidr.len() < 40 {
                    if let Some(c) = char::from_u32(ch) {
                        a.cidr.push(c);
                    }
                }
                a.dirty = true;
            } else if a.filter_focus {
                if ch == 8 {
                    a.filter.pop();
                } else if ch >= 32 && ch < 127 && a.filter.len() < 60 {
                    if let Some(c) = char::from_u32(ch) {
                        a.filter.push(c);
                    }
                }
                a.dirty = true;
            }
            return 0;
        }
        WM_KEYDOWN => {
            let vk = wp as i32;
            let a = app();
            let ctrl = (GetKeyState(VK_CONTROL) & 0x8000u16 as i16) != 0;
            match vk {
                VK_RETURN => match a.page {
                    state::PAGE_SCAN => {
                        a.cidr_focus = false;
                        a.start_scan();
                    }
                    state::PAGE_CAPTURE => {
                        a.filter_focus = false;
                        if a.capturing {
                            a.stop_capture();
                        } else {
                            a.start_capture();
                        }
                    }
                    state::PAGE_SIGNALS => a.start_signals(),
                    _ => {}
                },
                VK_ESCAPE => {
                    a.cidr_focus = false;
                    a.filter_focus = false;
                    a.selected = None;
                }
                VK_BACK => {
                    if a.cidr_focus {
                        a.cidr.pop();
                    } else if a.filter_focus {
                        a.filter.pop();
                    }
                }
                _ => {
                    if ctrl {
                        match vk {
                            0x31 => a.change_page(state::PAGE_SCAN),
                            0x32 => a.change_page(state::PAGE_CAPTURE),
                            0x33 => {
                                a.change_page(state::PAGE_SIGNALS);
                                if a.wifi.is_empty() && a.bt.is_empty() {
                                    a.start_signals();
                                }
                            }
                            0x34 => a.change_page(state::PAGE_ABOUT),
                            0x53 => {
                                if a.capturing {
                                    a.stop_capture();
                                } else {
                                    a.change_page(state::PAGE_CAPTURE);
                                    a.start_capture();
                                }
                            }
                            0x45 => export(a, "html"),
                            _ => {}
                        }
                    }
                }
            }
            a.dirty = true;
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_TIMER => {
            let a = app();
            a.tick(GetTickCount64());
            let changed = a.pump();
            if changed || a.needs_frame() {
                InvalidateRect(hwnd, std::ptr::null(), 0);
            }
            return 0;
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            return 0;
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

fn state_cursor_hand() -> *const u16 {
    32649 as *const u16
}

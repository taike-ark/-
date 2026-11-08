//! 控制台美化：ANSI 颜色、宽度对齐（含中文）、表格渲染。

use std::io::Write;

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";
pub const WHITE: &str = "\x1b[37m";
pub const GREY: &str = "\x1b[90m";
pub const BRGREEN: &str = "\x1b[92m";
pub const BRCYAN: &str = "\x1b[96m";

/// Windows 下打开 ANSI 虚拟终端处理
#[cfg(target_os = "windows")]
mod k32 {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
        pub fn GetConsoleMode(h: *mut std::ffi::c_void, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(h: *mut std::ffi::c_void, mode: u32) -> i32;
        pub fn SetConsoleOutputCP(cp: u32) -> i32;
        pub fn SetConsoleTitleW(title: *const u16) -> i32;
    }
}

#[cfg(target_os = "windows")]
pub fn enable_ansi() -> bool {
    unsafe {
        k32::SetConsoleOutputCP(65001);
        let h = k32::GetStdHandle(0xFFFF_FFF5); // STD_OUTPUT_HANDLE
        let mut mode: u32 = 0;
        if k32::GetConsoleMode(h, &mut mode) != 0 {
            // ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            if k32::SetConsoleMode(h, mode | 0x0004) != 0 {
                return true;
            }
        }
        false
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enable_ansi() -> bool {
    true
}

pub fn set_title(title: &str) {
    #[cfg(target_os = "windows")]
    {
        let mut wide: Vec<u16> = title.encode_utf16().collect();
        wide.push(0);
        unsafe {
            k32::SetConsoleTitleW(wide.as_ptr());
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = title;
    }
}

#[derive(Clone)]
pub struct Term {
    pub color: bool,
    pub tty: bool,
}

impl Term {
    pub fn new(no_color: bool) -> Term {
        let is_tty = atty();
        let ok = !no_color && is_tty && enable_ansi();
        Term { color: ok, tty: is_tty }
    }

    pub fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("{}{}{}", code, s, RESET)
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.paint(BOLD, s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.paint(DIM, s)
    }
    pub fn green(&self, s: &str) -> String {
        self.paint(GREEN, s)
    }
    pub fn brgreen(&self, s: &str) -> String {
        self.paint(BRGREEN, s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.paint(CYAN, s)
    }
    pub fn brcyan(&self, s: &str) -> String {
        self.paint(BRCYAN, s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.paint(YELLOW, s)
    }
    pub fn red(&self, s: &str) -> String {
        self.paint(RED, s)
    }
    pub fn grey(&self, s: &str) -> String {
        self.paint(GREY, s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.paint(MAGENTA, s)
    }
}

#[cfg(target_os = "windows")]
pub fn atty() -> bool {
    unsafe {
        let h = k32::GetStdHandle(0xFFFF_FFF5);
        let mut mode: u32 = 0;
        k32::GetConsoleMode(h, &mut mode) != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn atty() -> bool {
    true
}

/// 显示宽度（中文/全角算 2）
pub fn width(s: &str) -> usize {
    let mut w = 0usize;
    for c in s.chars() {
        if c == '\x1b' {
            // 跳过 ANSI 序列
            continue;
        }
        let cp = c as u32;
        let wide = (0x1100..=0x115F).contains(&cp)
            || (0x2E80..=0xA4CF).contains(&cp)
            || (0xAC00..=0xD7A3).contains(&cp)
            || (0xF900..=0xFAFF).contains(&cp)
            || (0xFE30..=0xFE4F).contains(&cp)
            || (0xFF00..=0xFF60).contains(&cp)
            || (0xFFE0..=0xFFE6).contains(&cp)
            || (0x1F300..=0x1FAFF).contains(&cp);
        w += if wide { 2 } else { 1 };
    }
    w
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut inesc = false;
    for c in s.chars() {
        if inesc {
            if c.is_ascii_alphabetic() {
                inesc = false;
            }
            continue;
        }
        if c == '\x1b' {
            inesc = true;
            continue;
        }
        out.push(c);
    }
    out
}

fn pad(s: &str, to: usize) -> String {
    let w = width(&strip_ansi(s));
    if w >= to {
        s.to_string()
    } else {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(to - w));
        out
    }
}

/// 渲染表格
pub fn table(t: &Term, headers: &[&str], rows: &[Vec<String>], sep: bool) {
    let mut widths: Vec<usize> = headers.iter().map(|h| width(h)).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(width(&strip_ansi(c)));
            }
        }
    }
    let line = |cells: &[String], is_head: bool| {
        let mut out = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                out.push_str(if sep { "  " } else { " " });
            }
            let padded = pad(c, widths[i]);
            if is_head {
                out.push_str(&t.paint(DIM, &padded));
            } else {
                out.push_str(&padded);
            }
        }
        println!("{}", out.trim_end());
    };
    let heads: Vec<String> = headers.iter().map(|s| s.to_string()).collect();
    line(&heads, true);
    let total: usize = widths.iter().sum::<usize>() + (if sep { 2 } else { 1 }) * (widths.len() - 1);
    println!("{}", t.grey(&"─".repeat(total.max(10))));
    for r in rows {
        line(r, false);
    }
}

pub fn flush() {
    let _ = std::io::stdout().flush();
}

pub fn progress(t: &Term, label: &str, done: usize, total: usize, extra: &str) {
    if total == 0 {
        return;
    }
    let pct = (done * 100 / total).min(100);
    let bar_w = 26usize;
    let filled = (pct * bar_w / 100).min(bar_w);
    let bar = format!(
        "{}{}",
        "█".repeat(filled),
        t.grey(&"░".repeat(bar_w - filled))
    );
    if t.tty {
        print!(
            "\r  {} {} {}% ({}/{}) {}",
            t.cyan(label),
            bar,
            pct,
            done,
            total,
            extra
        );
        flush();
    } else {
        println!(
            "  {} {} {}% ({}/{}) {}",
            t.cyan(label),
            bar,
            pct,
            done,
            total,
            extra.trim()
        );
    }
}

pub fn clear_line(t: &Term) {
    if t.tty {
        print!("\r{}\r", " ".repeat(100));
        flush();
    }
}

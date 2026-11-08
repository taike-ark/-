//! 把系统 DLL 作为链接输入（rust-lld 从 DLL 导出表生成导入），
//! 这样 GNU/gnullvm 工具链也不需要 libgdi32.a / libgdiplus.a 导入库。
//! MSVC 工具链自带 Windows SDK 导入库，代码里用 #[cfg_attr(target_env = "msvc", ...)] 处理。

use std::path::Path;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env == "msvc" {
        return;
    }
    let sys = if Path::new("C:/Windows/System32/gdiplus.dll").exists() {
        "C:/Windows/System32"
    } else {
        "C:/Windows/SysWOW64"
    };
    for dll in ["gdi32", "gdiplus", "shell32"] {
        println!("cargo:rustc-link-arg={}/{}.dll", sys, dll);
    }
    println!("cargo:rerun-if-changed=build.rs");
}

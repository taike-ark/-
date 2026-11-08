//! Windows 上 shell32 通过 DLL 直链（GNU/gnullvm 无 libshell32.a）。
//! MSVC 工具链自带导入库，由 #[cfg_attr(target_env = "msvc", link(...))] 处理。

use std::path::Path;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env == "msvc" {
        return;
    }
    let sys = if Path::new("C:/Windows/System32/shell32.dll").exists() {
        "C:/Windows/System32"
    } else {
        "C:/Windows/SysWOW64"
    };
    println!("cargo:rustc-link-arg={}/shell32.dll", sys);
    println!("cargo:rerun-if-changed=build.rs");
}

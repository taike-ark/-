//! 平台抽象层：网卡、ARP 表、ICMP、反查域名。
//! Windows 走 iphlpapi/ws2_32 原生调用；Android/Linux 走 /proc 与 libc。

#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
pub use win::*;

#[cfg(not(target_os = "windows"))]
mod android;
#[cfg(not(target_os = "windows"))]
pub use android::*;

/// 本机网卡信息
#[derive(Clone, Debug)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    pub ip: u32,
    pub prefix: u8,
    pub mac: Option<String>,
    pub gateway: Option<u32>,
    pub is_default: bool,
}

impl Iface {
    pub fn cidr(&self) -> String {
        format!("{}/{}", crate::fmt_ip(self.ip), self.prefix)
    }
}

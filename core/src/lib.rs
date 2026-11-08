//! NetRadar core — 零依赖网络发现 / 端口扫描 / 抓包引擎。
//!
//! 设计目标:
//!   * 零第三方 crate（完全离线可构建）
//!   * Windows(桌面) 与 Android(arm64) 共用同一份扫描与抓包内核
//!   * 前端（Windows 控制台 / Android Java UI）只负责展示与调度

#![allow(dead_code)]

pub mod capture;
pub mod net;
pub mod oui;
pub mod platform;
pub mod report;
pub mod scan;
pub mod services;
#[cfg(target_os = "windows")]
pub mod signals;
#[cfg(not(target_os = "windows"))]
#[path = "signals_stub.rs"]
pub mod signals;

pub const VERSION: &str = "1.0.0";
pub const BUILD: &str = "2026.11";

/// 格式化 IPv4（内部统一使用"大端数值"表示，即 192.168.1.5 == 0xC0A80105）
pub fn fmt_ip(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn parse_ip(s: &str) -> Option<u32> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut v = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 {
            return None;
        }
        v[i] = p.parse::<u8>().ok()?;
    }
    Some(u32::from_be_bytes(v))
}

pub fn mac_vendor(mac: &str) -> Option<&'static str> {
    oui::lookup(mac)
}

/// 一个开放（或已知状态）端口
#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub service: &'static str,
    pub banner: Option<String>,
}

/// 单个主机扫描结果
#[derive(Clone, Debug, Default)]
pub struct Host {
    pub ip: u32,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<u32>,
    /// ARP / ICMP / TCP / ARP缓存
    pub methods: Vec<&'static str>,
    pub ports: Vec<PortInfo>,
    pub alive: bool,
}

impl Host {
    pub fn new(ip: u32) -> Self {
        Host {
            ip,
            alive: true,
            ..Default::default()
        }
    }
    pub fn ip_str(&self) -> String {
        fmt_ip(self.ip)
    }
    pub fn mac_str(&self) -> String {
        self.mac.clone().unwrap_or_else(|| "-".to_string())
    }
    pub fn vendor_str(&self) -> String {
        self.vendor.clone().unwrap_or_else(|| "-".to_string())
    }
    pub fn method_str(&self) -> String {
        self.methods.join("+")
    }
    pub fn add_method(&mut self, m: &'static str) {
        if !self.methods.iter().any(|x| *x == m) {
            self.methods.push(m);
        }
    }
    pub fn ports_str(&self) -> String {
        if self.ports.is_empty() {
            return "-".to_string();
        }
        self.ports
            .iter()
            .map(|p| {
                if p.service == "unknown" {
                    p.port.to_string()
                } else {
                    format!("{}/{}", p.port, p.service)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// 扫描期间产生的事件（供 UI 实时刷新）
#[derive(Clone, Debug)]
pub enum ScanEvent {
    /// 开始扫描网段
    Start { net: String, total: usize },
    /// 探测进度
    Progress { done: usize, total: usize },
    /// 发现存活主机（先于端口扫描）
    HostUp(Host),
    /// 端口发现
    PortOpen { ip: u32, port: u16, service: &'static str },
    /// 端口扫描进度
    PortProgress { done: usize, total: usize },
    /// 一般日志
    Log(String),
    /// 完成
    Done { alive: usize, scanned: usize, elapsed_ms: u128 },
}

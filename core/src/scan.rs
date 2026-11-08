//! 主机发现 + 端口扫描。ARP 缓存优先，其次 ICMP，再退化为 TCP 探测。

use crate::net::Net;
use crate::platform;
use crate::services;
use crate::{fmt_ip, Host, PortInfo, ScanEvent};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct ScanOpts {
    pub timeout_ms: u64,
    pub threads: usize,
    /// 要扫描的端口；为空表示只发现主机
    pub ports: Vec<u16>,
    pub use_icmp: bool,
    pub use_tcp: bool,
    pub resolve_names: bool,
    pub banner: bool,
}

impl Default for ScanOpts {
    fn default() -> Self {
        ScanOpts {
            timeout_ms: 400,
            threads: 128,
            ports: Vec::new(),
            use_icmp: true,
            use_tcp: true,
            resolve_names: true,
            banner: true,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    Open,
    Closed,
    Filtered,
}

fn sockaddr(ip: u32, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(ip.to_be_bytes()), port)
}

/// TCP connect 探测（SYN 语义近似，无需管理员权限）
pub fn tcp_probe(ip: u32, port: u16, timeout_ms: u64) -> Probe {
    let t = Duration::from_millis(timeout_ms.max(20));
    match TcpStream::connect_timeout(&sockaddr(ip, port).into(), t) {
        Ok(_) => Probe::Open,
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Probe::Closed,
            _ => Probe::Filtered,
        },
    }
}

/// 抓取服务指纹（banner）
pub fn grab_banner(mut s: TcpStream, port: u16) -> Option<String> {
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(250)));
    let http_like = matches!(
        port,
        80 | 81 | 443 | 8080 | 8000 | 8008 | 8081 | 8088 | 8443 | 8888 | 9000
    );
    if http_like {
        let req = "HEAD / HTTP/1.0\r\nHost: netradar\r\nUser-Agent: NetRadar/1.0\r\nConnection: close\r\n\r\n";
        let _ = s.write_all(req.as_bytes());
    }
    let mut buf = [0u8; 512];
    let n = match s.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return None,
    };
    if n == 0 {
        return None;
    }
    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
    if http_like {
        for line in raw.lines() {
            let low = line.to_ascii_lowercase();
            if let Some(idx) = low.find("server:") {
                let v = line[idx + 7..].trim();
                if !v.is_empty() {
                    return Some(clip(v, 60));
                }
            }
        }
        if let Some(first) = raw.lines().next() {
            if first.starts_with("HTTP/") {
                return Some(clip(first, 60));
            }
        }
    }
    if let Some(first) = raw.lines().next() {
        if first.is_empty() {
            return None;
        }
        Some(clip(first, 60))
    } else {
        None
    }
}

fn clip(s: &str, n: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.chars().count() > n {
        cleaned.chars().take(n).collect::<String>()
    } else {
        cleaned
    }
}

/// 单主机存活探测
pub fn probe_host(ip: u32, opts: &ScanOpts, arp: &HashMap<u32, String>) -> Option<Host> {
    let mut h = Host::new(ip);
    let mut alive = false;

    if let Some(mac) = arp.get(&ip) {
        h.mac = Some(mac.clone());
        h.add_method("ARP");
        alive = true;
    }

    if !alive && opts.use_icmp {
        if let Some(rtt) = platform::ping(ip, opts.timeout_ms) {
            h.rtt_ms = Some(rtt);
            h.add_method("ICMP");
            alive = true;
        }
    }

    if !alive && opts.use_tcp {
        for &p in services::DISCOVERY_PORTS.iter().take(4) {
            match tcp_probe(ip, p, opts.timeout_ms) {
                Probe::Open => {
                    h.add_method("TCP");
                    alive = true;
                    h.ports.push(PortInfo {
                        port: p,
                        service: services::service_name(p),
                        banner: None,
                    });
                    break;
                }
                Probe::Closed => {
                    h.add_method("TCP");
                    alive = true;
                    break;
                }
                Probe::Filtered => {}
            }
        }
    }

    if alive {
        h.alive = true;
        Some(h)
    } else {
        None
    }
}

/// 反向解析主机名：总预算 1.5 秒，超时的解析不再等待
fn fill_names(hosts: &mut [Host], _threads: usize) {
    if hosts.is_empty() {
        return;
    }
    let out = Arc::new(Mutex::new(Vec::<(usize, String)>::new()));
    for (i, h) in hosts.iter().enumerate() {
        let out = Arc::clone(&out);
        let ip = h.ip;
        std::thread::spawn(move || {
            if let Some(n) = platform::reverse_dns(ip) {
                out.lock().unwrap().push((i, n));
            }
        });
    }
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
        if out.lock().unwrap().len() >= hosts.len() {
            break;
        }
    }
    let got = out.lock().unwrap().clone();
    for (i, n) in got {
        if i < hosts.len() {
            hosts[i].hostname = Some(n);
        }
    }
}

/// 完整扫描：主机发现 → 主机名 → 端口
pub fn discover<F>(
    net: Net,
    opts: &ScanOpts,
    cancel: &Arc<AtomicBool>,
    on_event: &mut F,
) -> Vec<Host>
where
    F: FnMut(ScanEvent),
{
    let start = Instant::now();
    let my_ips: Vec<u32> = platform::interfaces().iter().map(|i| i.ip).collect();
    let mut targets: Vec<u32> = net.hosts_vec();
    targets.retain(|ip| !my_ips.contains(ip));
    if targets.len() > 8192 {
        targets.truncate(8192);
    }
    let total = targets.len();
    on_event(ScanEvent::Start {
        net: net.to_cidr(),
        total,
    });

    let arp = platform::arp_table();
    let mut hosts: Vec<Host> = Vec::new();
    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let nthreads = opts.threads.clamp(1, 1024).min(total.max(1));
    let idx = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);

    std::thread::scope(|s| {
        for _ in 0..nthreads {
            let tx = tx.clone();
            let targets_ref = &targets;
            let arp_ref = &arp;
            let idx_ref = &idx;
            let done_ref = &done;
            s.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                if i >= targets_ref.len() {
                    break;
                }
                let ip = targets_ref[i];
                if let Some(h) = probe_host(ip, opts, arp_ref) {
                    let _ = tx.send(ScanEvent::HostUp(h));
                }
                let d = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = tx.send(ScanEvent::Progress { done: d, total });
            });
        }
        drop(tx);
        while let Ok(ev) = rx.recv() {
            if let ScanEvent::HostUp(h) = &ev {
                hosts.push(h.clone());
            }
            on_event(ev);
        }
    });

    if hosts.is_empty() {
        on_event(ScanEvent::Log(
            "未发现存活主机（网段可能错误 / 跨网段 / 防火墙全拦截）".into(),
        ));
    }

    // 扫描后 ARP 缓存补齐 MAC（ICMP/TCP 探测会触发 ARP 解析）
    let arp2 = platform::arp_table();
    // ARP 握手成功 = 主机一定在线，即便它屏蔽了 ICMP/TCP（校园网/企业防火墙很常见）
    for ip in &targets {
        if hosts.iter().any(|h| h.ip == *ip) {
            continue;
        }
        if let Some(mac) = arp2.get(ip) {
            let mut h = Host::new(*ip);
            h.mac = Some(mac.clone());
            h.add_method("ARP");
            h.vendor = crate::oui::lookup(mac).map(|s| s.to_string());
            on_event(ScanEvent::HostUp(h.clone()));
            hosts.push(h);
        }
    }
    for h in hosts.iter_mut() {
        if h.mac.is_none() {
            if let Some(mac) = arp2.get(&h.ip) {
                h.mac = Some(mac.clone());
            }
        }
        if let Some(mac) = &h.mac {
            if h.vendor.is_none() {
                h.vendor = crate::oui::lookup(mac).map(|s| s.to_string());
            }
        }
    }

    if opts.resolve_names && !hosts.is_empty() {
        on_event(ScanEvent::Log("解析主机名…".into()));
        fill_names(&mut hosts, opts.threads.min(32));
    }

    if !opts.ports.is_empty() && !hosts.is_empty() {
        scan_ports_multi(&mut hosts, &opts.ports, opts, cancel, on_event);
    }

    hosts.sort_by_key(|h| h.ip);
    on_event(ScanEvent::Done {
        alive: hosts.len(),
        scanned: total,
        elapsed_ms: start.elapsed().as_millis(),
    });
    hosts
}

/// 对多台主机批量扫端口
pub fn scan_ports_multi<F>(
    hosts: &mut [Host],
    ports: &[u16],
    opts: &ScanOpts,
    cancel: &Arc<AtomicBool>,
    on_event: &mut F,
) where
    F: FnMut(ScanEvent),
{
    if ports.is_empty() || hosts.is_empty() {
        return;
    }
    let mut jobs: Vec<(usize, u32, u16)> = Vec::new();
    for (hi, h) in hosts.iter().enumerate() {
        for &p in ports {
            jobs.push((hi, h.ip, p));
        }
    }
    let total = jobs.len();
    on_event(ScanEvent::Log(format!(
        "端口扫描: {} 台主机 × {} 端口 = {} 个探测",
        hosts.len(),
        ports.len(),
        total
    )));

    let results: Mutex<Vec<(usize, PortInfo)>> = Mutex::new(Vec::new());
    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let idx = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let nthreads = opts.threads.clamp(1, 1024).min(total.max(1));

    std::thread::scope(|s| {
        for _ in 0..nthreads {
            let tx = tx.clone();
            let jobs_ref = &jobs;
            let results_ref = &results;
            let idx_ref = &idx;
            let done_ref = &done;
            s.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                if i >= jobs_ref.len() {
                    break;
                }
                let (hi, ip, port) = jobs_ref[i];
                if tcp_probe(ip, port, opts.timeout_ms) == Probe::Open {
                    let service = services::service_name(port);
                    let info = PortInfo {
                        port,
                        service,
                        banner: None,
                    };
                    results_ref.lock().unwrap().push((hi, info));
                    let _ = tx.send(ScanEvent::PortOpen { ip, port, service });
                }
                let d = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                if d % 64 == 0 || d == total {
                    let _ = tx.send(ScanEvent::PortProgress { done: d, total });
                }
            });
        }
        drop(tx);
        while let Ok(ev) = rx.recv() {
            on_event(ev);
        }
    });

    for (hi, p) in results.into_inner().unwrap() {
        if hi < hosts.len() {
            hosts[hi].ports.push(p);
        }
    }
    for h in hosts.iter_mut() {
        h.ports.sort_by_key(|p| p.port);
    }
}

/// 单主机端口扫描（--scan <ip>）
pub fn scan_single<F>(
    ip: u32,
    ports: &[u16],
    opts: &ScanOpts,
    cancel: &Arc<AtomicBool>,
    on_event: &mut F,
) -> Host
where
    F: FnMut(ScanEvent),
{
    let start = Instant::now();
    let mut host = probe_host(ip, opts, &platform::arp_table()).unwrap_or_else(|| Host::new(ip));
    host.alive = true;
    if let Some(mac) = &host.mac {
        if host.vendor.is_none() {
            host.vendor = crate::oui::lookup(mac).map(|s| s.to_string());
        }
    }
    if opts.resolve_names {
        if let Some(n) = platform::reverse_dns(ip) {
            host.hostname = Some(n);
        }
    }
    on_event(ScanEvent::Start {
        net: format!("{}/32", fmt_ip(ip)),
        total: ports.len(),
    });

    let results: Mutex<Vec<PortInfo>> = Mutex::new(Vec::new());
    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let idx = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let total = ports.len();
    let nthreads = opts.threads.clamp(1, 512).min(total.max(1));

    std::thread::scope(|s| {
        for _ in 0..nthreads {
            let tx = tx.clone();
            let results_ref = &results;
            let idx_ref = &idx;
            let done_ref = &done;
            s.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                if i >= ports.len() {
                    break;
                }
                let port = ports[i];
                if tcp_probe(ip, port, opts.timeout_ms) == Probe::Open {
                    let mut banner = None;
                    if opts.banner {
                        if let Ok(st) = TcpStream::connect_timeout(
                            &sockaddr(ip, port).into(),
                            Duration::from_millis(opts.timeout_ms.max(50)),
                        ) {
                            banner = grab_banner(st, port);
                        }
                    }
                    let info = PortInfo {
                        port,
                        service: services::service_name(port),
                        banner,
                    };
                    results_ref.lock().unwrap().push(info);
                    let _ = tx.send(ScanEvent::PortOpen {
                        ip,
                        port,
                        service: services::service_name(port),
                    });
                }
                let d = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                if d % 32 == 0 || d == total {
                    let _ = tx.send(ScanEvent::PortProgress { done: d, total });
                }
            });
        }
        drop(tx);
        while let Ok(ev) = rx.recv() {
            on_event(ev);
        }
    });

    host.ports = results.into_inner().unwrap();
    host.ports.sort_by_key(|p| p.port);
    on_event(ScanEvent::Done {
        alive: 1,
        scanned: total,
        elapsed_ms: start.elapsed().as_millis(),
    });
    host
}

//! 抓包引擎：以太网/IP 报文解析、BPF 风格过滤、pcap 落盘。
//! Windows 后端优先 Npcap（wpcap.dll），否则用系统 RAW SOCKET(SIO_RCVALL)。

use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::fmt_ip;

/// 解析后的关键字段（供过滤表达式使用）
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    pub l4: u8, // 6=tcp 17=udp 1=icmp 0=其他
    pub is_arp: bool,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub ts_us: u64,
    pub stamp: String,
    pub len: u32,
    pub src: String,
    pub dst: String,
    pub proto: &'static str,
    pub info: String,
    pub raw: Vec<u8>,
    pub l2: bool,
}

pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// 本地时间 HH:MM:SS.mmm
#[cfg(target_os = "windows")]
pub fn local_hms() -> String {
    #[repr(C)]
    struct SystemTimeHms {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocalTime(st: *mut SystemTimeHms);
    }
    let mut st = SystemTimeHms {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        milliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        st.hour, st.minute, st.second, st.milliseconds
    )
}

#[cfg(not(target_os = "windows"))]
pub fn local_hms() -> String {
    let us = now_us();
    let secs = us / 1_000_000;
    let ms = (us / 1000) % 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms)
}

/* ------------------------------- 报文解析 ------------------------------- */

fn tcp_flags_str(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 {
        s.push('F');
    }
    if flags & 0x02 != 0 {
        s.push('S');
    }
    if flags & 0x04 != 0 {
        s.push('R');
    }
    if flags & 0x08 != 0 {
        s.push('P');
    }
    if flags & 0x10 != 0 {
        s.push('A');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

/// linktype: 1=Ethernet, 101=RAW IP
pub fn parse_packet(linktype: u32, data: &[u8], ts_us: u64) -> Option<(Parsed, Packet)> {
    let mut p = Parsed::default();
    let mut off = 0usize;
    let mut l2 = false;

    if linktype == 1 {
        if data.len() < 14 {
            return None;
        }
        l2 = true;
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        off = 14;
        if ethertype == 0x0806 {
            // ARP
            if data.len() < off + 28 {
                return None;
            }
            let op = u16::from_be_bytes([data[off + 6], data[off + 7]]);
            let sha = &data[off + 8..off + 14];
            let spa = &data[off + 14..off + 18];
            let tpa = &data[off + 24..off + 28];
            let sip = u32::from_be_bytes([spa[0], spa[1], spa[2], spa[3]]);
            let tip = u32::from_be_bytes([tpa[0], tpa[1], tpa[2], tpa[3]]);
            let mac = sha
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":");
            p.is_arp = true;
            p.src_ip = sip;
            p.dst_ip = tip;
            let info = if op == 1 {
                format!("who-has {} tell {}", fmt_ip(tip), fmt_ip(sip))
            } else {
                format!("{} is-at {} → {}", fmt_ip(sip), mac, fmt_ip(tip))
            };
            let pkt = Packet {
                ts_us,
                stamp: local_hms(),
                len: data.len() as u32,
                src: mac,
                dst: "broadcast".into(),
                proto: "ARP",
                info,
                raw: data.to_vec(),
                l2,
            };
            return Some((p, pkt));
        } else if ethertype != 0x0800 {
            return None;
        }
    } else if linktype == 113 {
        // Linux SLL
        if data.len() < 16 {
            return None;
        }
        let ethertype = u16::from_be_bytes([data[14], data[15]]);
        if ethertype != 0x0800 {
            return None;
        }
        off = 16;
    }

    // IPv4
    if data.len() < off + 20 {
        return None;
    }
    let ver_ihl = data[off];
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ((ver_ihl & 0x0F) as usize) * 4;
    let proto = data[off + 9];
    let total_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
    let sip = u32::from_be_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]);
    let dip = u32::from_be_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]);
    p.src_ip = sip;
    p.dst_ip = dip;
    p.l4 = proto;
    let l4off = off + ihl;
    let payload_len = total_len.saturating_sub(ihl);

    let (proto_name, info) = match proto {
        6 => {
            if data.len() < l4off + 20 {
                return None;
            }
            let sport = u16::from_be_bytes([data[l4off], data[l4off + 1]]);
            let dport = u16::from_be_bytes([data[l4off + 2], data[l4off + 3]]);
            let flags = data[l4off + 13];
            p.src_port = sport;
            p.dst_port = dport;
            (
                "TCP",
                format!(
                    "{} → {} flags={} len={}",
                    sport,
                    dport,
                    tcp_flags_str(flags),
                    payload_len.saturating_sub(20)
                ),
            )
        }
        17 => {
            if data.len() < l4off + 8 {
                return None;
            }
            let sport = u16::from_be_bytes([data[l4off], data[l4off + 1]]);
            let dport = u16::from_be_bytes([data[l4off + 2], data[l4off + 3]]);
            p.src_port = sport;
            p.dst_port = dport;
            ("UDP", format!("{} → {} len={}", sport, dport, payload_len.saturating_sub(8)))
        }
        1 => {
            let t = data.get(l4off).copied().unwrap_or(0);
            let name = match t {
                0 => "echo-reply",
                3 => "dest-unreachable",
                8 => "echo-request",
                11 => "time-exceeded",
                5 => "redirect",
                _ => "icmp",
            };
            ("ICMP", name.to_string())
        }
        2 => ("IGMP", String::new()),
        47 => ("GRE", String::new()),
        50 => ("ESP", String::new()),
        51 => ("AH", String::new()),
        _ => ("IP", format!("proto={}", proto)),
    };

    let src = if p.src_port != 0 {
        format!("{}:{}", fmt_ip(sip), p.src_port)
    } else {
        fmt_ip(sip)
    };
    let dst = if p.dst_port != 0 {
        format!("{}:{}", fmt_ip(dip), p.dst_port)
    } else {
        fmt_ip(dip)
    };

    let pkt = Packet {
        ts_us,
        stamp: local_hms(),
        len: data.len() as u32,
        src,
        dst,
        proto: proto_name,
        info,
        raw: data.to_vec(),
        l2,
    };
    Some((p, pkt))
}

/* ------------------------------- 过滤表达式 ------------------------------- */

#[derive(Clone, Debug)]
pub enum Filter {
    All,
    Proto(u8),
    Arp,
    Host(u32),
    SrcHost(u32),
    DstHost(u32),
    Port(u16),
    SrcPort(u16),
    DstPort(u16),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

impl Filter {
    pub fn parse(expr: &str) -> Result<Filter, String> {
        let toks = tokenize(expr);
        if toks.is_empty() {
            return Ok(Filter::All);
        }
        let mut pos = 0usize;
        let f = parse_or(&toks, &mut pos)?;
        if pos != toks.len() {
            return Err(format!("无法解析的过滤表达式片段: {}", toks[pos]));
        }
        Ok(f)
    }

    pub fn matches(&self, p: &Parsed) -> bool {
        match self {
            Filter::All => true,
            Filter::Proto(x) => p.l4 == *x && !p.is_arp,
            Filter::Arp => p.is_arp,
            Filter::Host(ip) => p.src_ip == *ip || p.dst_ip == *ip,
            Filter::SrcHost(ip) => p.src_ip == *ip,
            Filter::DstHost(ip) => p.dst_ip == *ip,
            Filter::Port(x) => p.src_port == *x || p.dst_port == *x,
            Filter::SrcPort(x) => p.src_port == *x,
            Filter::DstPort(x) => p.dst_port == *x,
            Filter::And(a, b) => a.matches(p) && b.matches(p),
            Filter::Or(a, b) => a.matches(p) || b.matches(p),
            Filter::Not(a) => !a.matches(p),
        }
    }
}

fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    out.push(cur.clone());
                    cur.clear();
                }
                out.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(cur.clone());
                    cur.clear();
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.into_iter()
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn parse_or(t: &[String], pos: &mut usize) -> Result<Filter, String> {
    let mut left = parse_and(t, pos)?;
    while *pos < t.len() && (t[*pos] == "or" || t[*pos] == "||") {
        *pos += 1;
        let right = parse_and(t, pos)?;
        left = Filter::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(t: &[String], pos: &mut usize) -> Result<Filter, String> {
    let mut left = parse_atom(t, pos)?;
    loop {
        if *pos >= t.len() {
            break;
        }
        let tok = t[*pos].clone();
        if tok == "and" || tok == "&&" {
            *pos += 1;
        } else if tok == "or" || tok == "||" || tok == ")" {
            break;
        }
        // BPF 风格隐式 AND: "tcp port 443"
        let right = parse_atom(t, pos)?;
        left = Filter::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_atom(t: &[String], pos: &mut usize) -> Result<Filter, String> {
    if *pos >= t.len() {
        return Err("过滤表达式意外结束".into());
    }
    let tok = t[*pos].clone();
    match tok.as_str() {
        "not" | "!" => {
            *pos += 1;
            let inner = parse_atom(t, pos)?;
            Ok(Filter::Not(Box::new(inner)))
        }
        "(" => {
            *pos += 1;
            let inner = parse_or(t, pos)?;
            if *pos < t.len() && t[*pos] == ")" {
                *pos += 1;
            }
            Ok(inner)
        }
        "tcp" => {
            *pos += 1;
            Ok(Filter::Proto(6))
        }
        "udp" => {
            *pos += 1;
            Ok(Filter::Proto(17))
        }
        "icmp" => {
            *pos += 1;
            Ok(Filter::Proto(1))
        }
        "arp" => {
            *pos += 1;
            Ok(Filter::Arp)
        }
        "ip" => {
            *pos += 1;
            Ok(Filter::Proto(0xff))
        }
        "host" | "src" | "dst" | "port" => {
            *pos += 1;
            let qualifier = tok;
            let mut what = "host".to_string();
            if qualifier == "port" {
                what = "port".into();
            }
            // src host / src port
            if *pos < t.len() && (t[*pos] == "host" || t[*pos] == "port") {
                what = t[*pos].clone();
                *pos += 1;
            }
            let val = t.get(*pos).cloned().ok_or_else(|| "过滤表达式缺少参数".to_string())?;
            *pos += 1;
            if what == "port" {
                let port: u16 = val.parse().map_err(|_| format!("非法端口: {}", val))?;
                Ok(match qualifier.as_str() {
                    "src" => Filter::SrcPort(port),
                    "dst" => Filter::DstPort(port),
                    _ => Filter::Port(port),
                })
            } else {
                let ip = crate::parse_ip(&val).ok_or_else(|| format!("非法地址: {}", val))?;
                Ok(match qualifier.as_str() {
                    "src" => Filter::SrcHost(ip),
                    "dst" => Filter::DstHost(ip),
                    _ => Filter::Host(ip),
                })
            }
        }
        other => {
            // 允许直接写 IP 或端口
            if let Some(ip) = crate::parse_ip(other) {
                *pos += 1;
                Ok(Filter::Host(ip))
            } else if let Ok(p) = other.parse::<u16>() {
                *pos += 1;
                Ok(Filter::Port(p))
            } else {
                Err(format!("无法识别的过滤词: {}", other))
            }
        }
    }
}

/* ------------------------------- pcap 写入 ------------------------------- */

pub struct PcapWriter {
    f: File,
    pub linktype: u32,
    pub count: u64,
}

impl PcapWriter {
    pub fn create(path: &str, linktype: u32) -> std::io::Result<PcapWriter> {
        let mut f = File::create(path)?;
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        hdr.extend_from_slice(&2u16.to_le_bytes());
        hdr.extend_from_slice(&4u16.to_le_bytes());
        hdr.extend_from_slice(&0i32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&262_144u32.to_le_bytes());
        hdr.extend_from_slice(&linktype.to_le_bytes());
        f.write_all(&hdr)?;
        Ok(PcapWriter {
            f,
            linktype,
            count: 0,
        })
    }

    pub fn write(&mut self, ts_us: u64, data: &[u8]) -> std::io::Result<()> {
        let sec = (ts_us / 1_000_000) as u32;
        let usec = (ts_us % 1_000_000) as u32;
        let mut rec = Vec::with_capacity(16 + data.len());
        rec.extend_from_slice(&sec.to_le_bytes());
        rec.extend_from_slice(&usec.to_le_bytes());
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
        rec.extend_from_slice(data);
        self.f.write_all(&rec)?;
        self.count += 1;
        Ok(())
    }
}

/* ------------------------------- 抓包会话 ------------------------------- */

#[derive(Clone, Debug, Default)]
pub struct CaptureOpts {
    pub iface: Option<u32>,
    pub filter: Option<String>,
    pub count: usize,
    pub duration_ms: u64,
    pub pcap_out: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CaptureStats {
    pub packets: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub arp: u64,
    pub other: u64,
    pub bytes: u64,
    pub backend: String,
    pub linktype: u32,
    pub pcap_path: Option<String>,
}

pub struct Capturer<F: FnMut(&Packet)> {
    pub filter: Filter,
    pub stats: CaptureStats,
    pub writer: Option<PcapWriter>,
    pub sink: F,
    pub print: bool,
}

impl<F: FnMut(&Packet)> Capturer<F> {
    pub fn new(filter: Filter, sink: F, print: bool) -> Self {
        Capturer {
            filter,
            stats: CaptureStats::default(),
            writer: None,
            sink,
            print,
        }
    }

    pub fn on_raw(&mut self, linktype: u32, data: &[u8]) -> bool {
        let ts = now_us();
        if let Some((parsed, pkt)) = parse_packet(linktype, data, ts) {
            if !self.filter.matches(&parsed) {
                return false;
            }
            self.stats.packets += 1;
            self.stats.bytes += pkt.len as u64;
            match pkt.proto {
                "TCP" => self.stats.tcp += 1,
                "UDP" => self.stats.udp += 1,
                "ICMP" => self.stats.icmp += 1,
                "ARP" => self.stats.arp += 1,
                _ => self.stats.other += 1,
            }
            if let Some(w) = self.writer.as_mut() {
                let _ = w.write(ts, data);
            }
            if self.print {
                println!(
                    "{}  {:<4} {:<28} → {:<28} {}",
                    pkt.stamp, pkt.proto, pkt.src, pkt.dst, pkt.info
                );
            }
            (self.sink)(&pkt);
            true
        } else {
            false
        }
    }
}

fn should_stop(opts: &CaptureOpts, stats: &CaptureStats, start: Instant, cancel: &Arc<AtomicBool>) -> bool {
    if cancel.load(Ordering::Relaxed) {
        return true;
    }
    if opts.count > 0 && stats.packets >= opts.count as u64 {
        return true;
    }
    if opts.duration_ms > 0 && start.elapsed().as_millis() >= opts.duration_ms as u128 {
        return true;
    }
    false
}

/* ---------------------------- Windows: Npcap ---------------------------- */

#[cfg(target_os = "windows")]
mod npcap {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int, c_uint, c_void};
    use std::ptr;

    #[allow(non_snake_case)]
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const c_char) -> *mut c_void;
        fn GetProcAddress(h: *mut c_void, name: *const c_char) -> *mut c_void;
        fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
    }

    #[repr(C)]
    pub struct PcapAddr {
        pub next: *mut PcapAddr,
        pub addr: *mut c_void,
        pub netmask: *mut c_void,
        pub broadaddr: *mut c_void,
        pub dstaddr: *mut c_void,
    }

    #[repr(C)]
    pub struct PcapIf {
        pub next: *mut PcapIf,
        pub name: *mut c_char,
        pub description: *mut c_char,
        pub addresses: *mut PcapAddr,
        pub flags: c_uint,
    }

    #[repr(C)]
    pub struct PcapPkthdr {
        pub ts_sec: u32,
        pub ts_usec: u32,
        pub caplen: u32,
        pub len: u32,
    }

    type FindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
    type FreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
    type OpenLive =
        unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
    type NextEx =
        unsafe extern "C" fn(*mut c_void, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
    type Close = unsafe extern "C" fn(*mut c_void);
    type DataLink = unsafe extern "C" fn(*mut c_void) -> c_int;
    type BreakLoop = unsafe extern "C" fn(*mut c_void);

    pub struct Npcap {
        pub findalldevs: FindAllDevs,
        pub freealldevs: FreeAllDevs,
        pub open_live: OpenLive,
        pub next_ex: NextEx,
        pub close: Close,
        pub datalink: DataLink,
        pub breakloop: BreakLoop,
    }

    pub fn load() -> Option<Npcap> {
        unsafe {
            let mut h = LoadLibraryA(b"wpcap.dll\0".as_ptr() as *const c_char);
            if h.is_null() {
                h = GetModuleHandleA(b"wpcap.dll\0".as_ptr() as *const c_char);
            }
            if h.is_null() {
                return None;
            }
            macro_rules! sym {
                ($n:literal) => {{
                    let p = GetProcAddress(h, concat!($n, "\0").as_ptr() as *const c_char);
                    if p.is_null() {
                        return None;
                    }
                    std::mem::transmute(p)
                }};
            }
            Some(Npcap {
                findalldevs: sym!("pcap_findalldevs"),
                freealldevs: sym!("pcap_freealldevs"),
                open_live: sym!("pcap_open_live"),
                next_ex: sym!("pcap_next_ex"),
                close: sym!("pcap_close"),
                datalink: sym!("pcap_datalink"),
                breakloop: sym!("pcap_breakloop"),
            })
        }
    }

    pub fn cstr(p: *const c_char) -> String {
        if p.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p).to_string_lossy().to_string() }
        }
    }

    pub fn list_devices(np: &Npcap) -> Vec<(String, String)> {
        let mut out = Vec::new();
        unsafe {
            let mut devs: *mut PcapIf = ptr::null_mut();
            let mut errbuf = [0i8; 256];
            if (np.findalldevs)(&mut devs, errbuf.as_mut_ptr() as *mut c_char) != 0 {
                return out;
            }
            let mut cur = devs;
            let mut guard = 0;
            while !cur.is_null() && guard < 128 {
                guard += 1;
                let it = &*cur;
                out.push((cstr(it.name), cstr(it.description)));
                cur = it.next;
            }
            (np.freealldevs)(devs);
        }
        out
    }
}

/* ---------------------------- 抓包主流程 ---------------------------- */

pub fn list_capture_devices() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        if let Some(np) = npcap::load() {
            let mut out = Vec::new();
            for (name, desc) in npcap::list_devices(&np) {
                out.push(format!("{}\t{}", desc, name));
            }
            if !out.is_empty() {
                return out;
            }
        }
        let mut out = Vec::new();
        for i in crate::platform::interfaces() {
            out.push(format!(
                "[RAW] {} ({}) {}\t{}",
                i.name,
                i.cidr(),
                i.mac.clone().unwrap_or_default(),
                i.index
            ));
        }
        out
    }
    #[cfg(not(target_os = "windows"))]
    {
        crate::platform::interfaces()
            .iter()
            .map(|i| format!("{} ({})", i.name, i.cidr()))
            .collect()
    }
}

/// 启动抓包。返回统计信息。
pub fn run<F: FnMut(&Packet)>(
    opts: &CaptureOpts,
    cancel: &Arc<AtomicBool>,
    sink: F,
    print: bool,
) -> Result<CaptureStats, String> {
    let filter = match &opts.filter {
        Some(f) if !f.trim().is_empty() => Filter::parse(f)?,
        _ => Filter::All,
    };
    let mut cap = Capturer::new(filter, sink, print);
    if let Some(path) = &opts.pcap_out {
        let linktype = if crate::capture::npcap_available() { 1 } else { 101 };
        let w = PcapWriter::create(path, linktype).map_err(|e| format!("无法创建 pcap 文件: {}", e))?;
        cap.stats.pcap_path = Some(path.clone());
        cap.writer = Some(w);
    }

    let start = Instant::now();
    #[cfg(target_os = "windows")]
    {
        let stats = run_windows(opts, cancel, &mut cap, start)?;
        return Ok(stats);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (opts, start);
        Err("该平台需通过 --capture-stdin 模式抓包（Android 由 VpnService 提供数据）".into())
    }
}

pub fn npcap_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        npcap::load().is_some()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn run_windows<F: FnMut(&Packet)>(
    opts: &CaptureOpts,
    cancel: &Arc<AtomicBool>,
    cap: &mut Capturer<F>,
    start: Instant,
) -> Result<CaptureStats, String> {
    // 优先 Npcap
    if let Some(np) = npcap::load() {
        if let Ok(stats) = run_npcap(&np, opts, cancel, cap, start) {
            return Ok(stats);
        }
    }
    run_raw_socket(opts, cancel, cap, start)
}

#[cfg(target_os = "windows")]
fn run_npcap<F: FnMut(&Packet)>(
    np: &npcap::Npcap,
    opts: &CaptureOpts,
    cancel: &Arc<AtomicBool>,
    cap: &mut Capturer<F>,
    start: Instant,
) -> Result<CaptureStats, String> {
    use std::os::raw::{c_char, c_void};
    let devs = npcap::list_devices(np);
    if devs.is_empty() {
        return Err("Npcap 未找到可用网卡".into());
    }
    let chosen = match opts.iface {
        Some(i) => devs.get(i as usize).cloned().unwrap_or_else(|| devs[0].clone()),
        None => devs
            .iter()
            .find(|(name, descend)| {
                let s = format!("{}{}", name, descend).to_ascii_lowercase();
                !s.contains("loopback") && !s.contains("npf_loopback")
            })
            .cloned()
            .unwrap_or_else(|| devs[0].clone()),
    };
    let name_c = std::ffi::CString::new(chosen.0.clone()).map_err(|e| e.to_string())?;
    let mut errbuf = [0i8; 256];
    let handle = unsafe {
        (np.open_live)(
            name_c.as_ptr(),
            262_144,
            1,
            500,
            errbuf.as_mut_ptr() as *mut c_char,
        )
    };
    if handle.is_null() {
        return Err("Npcap 打开网卡失败（需要管理员权限）".into());
    }
    cap.stats.backend = format!("Npcap: {}", chosen.1);
    let linktype = unsafe { (np.datalink)(handle) } as u32;
    cap.stats.linktype = linktype;
    if let Some(w) = cap.writer.as_mut() {
        if w.linktype != linktype {
            w.linktype = linktype;
        }
    }

    let mut stop = false;
    while !stop {
        if should_stop(opts, &cap.stats, start, cancel) {
            break;
        }
        let mut hdr: *mut npcap::PcapPkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        let rc = unsafe { (np.next_ex)(handle, &mut hdr, &mut data) };
        match rc {
            1 => {
                if hdr.is_null() || data.is_null() {
                    continue;
                }
                let caplen = unsafe { (*hdr).caplen as usize };
                let slice = unsafe { std::slice::from_raw_parts(data, caplen) };
                cap.on_raw(linktype, slice);
            }
            0 => continue,
            _ => stop = true,
        }
    }
    unsafe {
        (np.breakloop)(handle);
        (np.close)(handle);
    }
    let mut stats = cap.stats.clone();
    stats.backend = format!("Npcap: {}", chosen.1);
    stats.linktype = linktype;
    Ok(stats)
}

#[cfg(target_os = "windows")]
fn run_raw_socket<F: FnMut(&Packet)>(
    opts: &CaptureOpts,
    cancel: &Arc<AtomicBool>,
    cap: &mut Capturer<F>,
    start: Instant,
) -> Result<CaptureStats, String> {
    use crate::platform::{bind, closesocket, recv, setsockopt, socket, WSAIoctl, WSAGetLastError};
    use std::os::raw::{c_char, c_void};

    let ifaces = crate::platform::interfaces();
    let chosen = match opts.iface {
        Some(i) => ifaces.iter().find(|x| x.index == i).cloned(),
        None => ifaces.first().cloned(),
    };
    let iface = chosen.ok_or_else(|| "未找到可用网卡".to_string())?;

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }
    let sa = SockaddrIn {
        family: 2,
        port: 0,
        addr: iface.ip.to_be(),
        zero: [0; 8],
    };
    const AF_INET: i32 = 2;
    const SOCK_RAW: i32 = 3;
    const IPPROTO_IP: i32 = 0;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RCVTIMEO: i32 = 0x1006;
    const SO_RCVBUF: i32 = 0x1002;
    const SIO_RCVALL: u32 = 0x9800_0001;

    let s = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_IP) };
    if s == usize::MAX || s == 0 {
        return Err(format!(
            "创建 RAW 套接字失败 (WSA错误 {}): 需要以管理员身份运行",
            unsafe { WSAGetLastError() }
        ));
    }
    let rc = unsafe { bind(s, &sa as *const _ as *const c_void, 16) };
    if rc != 0 {
        unsafe {
            closesocket(s);
        }
        return Err(format!(
            "绑定网卡失败 (WSA错误 {})",
            unsafe { WSAGetLastError() }
        ));
    }
    // 接收缓冲区
    let bufsz: i32 = 4 * 1024 * 1024;
    unsafe {
        setsockopt(
            s,
            SOL_SOCKET,
            SO_RCVBUF,
            &bufsz as *const i32 as *const c_char,
            4,
        );
    }
    // 500ms 超时，保证可响应退出
    let tv = [500i32, 0i32]; // timeval
    unsafe {
        setsockopt(
            s,
            SOL_SOCKET,
            SO_RCVTIMEO,
            tv.as_ptr() as *const c_char,
            8,
        );
    }
    let mut on: u32 = 1;
    let mut ret: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            s,
            SIO_RCVALL,
            &mut on as *mut u32 as *mut c_void,
            4,
            std::ptr::null_mut(),
            0,
            &mut ret,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        unsafe {
            closesocket(s);
        }
        return Err(format!(
            "启用混杂接收失败 (WSA错误 {}): 需要管理员权限",
            err
        ));
    }

    cap.stats.backend = format!("RAW SOCKET: {} ({})", iface.name, iface.cidr());
    cap.stats.linktype = 101;
    let mut buf = vec![0u8; 65_535];
    let mut stop = false;
    while !stop {
        if should_stop(opts, &cap.stats, start, cancel) {
            break;
        }
        let n = unsafe { recv(s, buf.as_mut_ptr() as *mut c_char, buf.len() as i32, 0) };
        if n <= 0 {
            continue;
        }
        let slice = &buf[..n as usize];
        cap.on_raw(101, slice);
    }
    unsafe {
        closesocket(s);
    }
    let mut stats = cap.stats.clone();
    stats.backend = format!("RAW SOCKET: {} ({})", iface.name, iface.cidr());
    stats.linktype = 101;
    Ok(stats)
}

/// Android: 从 stdin 读取 (4字节大端长度 + 原始 IP 报文)，由 Java VpnService 投喂
pub fn run_stdin<F: FnMut(&Packet)>(
    opts: &CaptureOpts,
    cancel: &Arc<AtomicBool>,
    sink: F,
    print: bool,
) -> Result<CaptureStats, String> {
    let filter = match &opts.filter {
        Some(f) if !f.trim().is_empty() => Filter::parse(f)?,
        _ => Filter::All,
    };
    let mut cap = Capturer::new(filter, sink, print);
    cap.stats.linktype = 101;
    cap.stats.backend = "VPN stdin".into();
    if let Some(path) = &opts.pcap_out {
        cap.writer = Some(
            PcapWriter::create(path, 101).map_err(|e| format!("无法创建 pcap: {}", e))?,
        );
        cap.stats.pcap_path = Some(path.clone());
    }
    let start = Instant::now();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();

    while !should_stop(opts, &cap.stats, start, cancel) {
        let mut lenbuf = [0u8; 4];
        if handle.read_exact(&mut lenbuf).is_err() {
            break;
        }
        let len = u32::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > 65_535 {
            continue;
        }
        let mut buf = vec![0u8; len];
        if handle.read_exact(&mut buf).is_err() {
            break;
        }
        cap.on_raw(101, &buf);
    }
    Ok(cap.stats)
}

/// 供 Android 一次性解析单个报文（返回可读摘要）
pub fn describe(linktype: u32, data: &[u8]) -> String {
    match parse_packet(linktype, data, now_us()) {
        Some((_, p)) => format!(
            "{}  {:<4} {:<24} → {:<24} {}",
            p.stamp, p.proto, p.src, p.dst, p.info
        ),
        None => String::new(),
    }
}

/// 演示: 生成一段统计摘要
pub fn summary(stats: &CaptureStats, elapsed: Duration) -> String {
    format!(
        "抓包统计 [{}]  共 {} 包 / {} 字节 / {:.1}s\n  TCP {} | UDP {} | ICMP {} | ARP {} | 其他 {}{}",
        stats.backend,
        stats.packets,
        stats.bytes,
        elapsed.as_secs_f64(),
        stats.tcp,
        stats.udp,
        stats.icmp,
        stats.arp,
        stats.other,
        stats
            .pcap_path
            .as_ref()
            .map(|p| format!("\n  pcap 已保存: {}", p))
            .unwrap_or_default()
    )
}

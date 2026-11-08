//! 应用状态、动画状态与引擎线程桥接

use netradar_core::capture::{self, CaptureOpts};
use netradar_core::net::Net;
use netradar_core::platform;
use netradar_core::scan::{self, ScanOpts};
use netradar_core::services;
use netradar_core::signals;
use netradar_core::{ScanEvent, VERSION};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;

use crate::anim::{chase, Anim, Curve};
use crate::gfx::{Gp, Rect};
use crate::theme::Fonts;

pub const PAGE_SCAN: usize = 0;
pub const PAGE_CAPTURE: usize = 1;
pub const PAGE_SIGNALS: usize = 2;
pub const PAGE_ABOUT: usize = 3;

pub const ID_TAB_SCAN: u32 = 100;
pub const ID_TAB_CAPTURE: u32 = 101;
pub const ID_TAB_SIGNALS: u32 = 102;
pub const ID_TAB_ABOUT: u32 = 103;

pub const ID_SCAN_START: u32 = 200;
pub const ID_SCAN_STOP: u32 = 201;
pub const ID_CIDR: u32 = 202;
pub const ID_EXPORT_HTML: u32 = 203;
pub const ID_EXPORT_CSV: u32 = 204;
pub const ID_EXPORT_JSON: u32 = 205;

pub const ID_CAP_START: u32 = 300;
pub const ID_CAP_STOP: u32 = 301;
pub const ID_FILTER: u32 = 302;
pub const ID_CAP_SAVE: u32 = 303;
pub const ID_FILTER_ALL: u32 = 310;
pub const ID_FILTER_TCP: u32 = 311;
pub const ID_FILTER_UDP: u32 = 312;
pub const ID_FILTER_ICMP: u32 = 313;

pub const ID_SIG_REFRESH: u32 = 500;
pub const ID_SIG_LOCATION: u32 = 501;

pub const ID_MIN: u32 = 400;
pub const ID_MAX: u32 = 401;
pub const ID_CLOSE: u32 = 402;

#[derive(Clone, Debug)]
pub struct PktLine {
    pub stamp: String,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

#[derive(Clone, Debug)]
pub enum UiEvent {
    Scan(ScanEvent),
    Packet(PktLine),
    CapInfo(String),
    CapDone(u64, u64),
    Wifi(Result<Vec<signals::WifiAp>, String>),
    Bt(Result<(Vec<signals::BtRadio>, Vec<signals::BtDevice>), String>),
}

#[derive(Clone, Debug)]
pub struct HostRow {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub name: String,
    pub method: String,
    pub rtt: i32,
    pub ports: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct WifiRow {
    pub ssid: String,
    pub bssid: String,
    pub rssi: i32,
    pub quality: u32,
    pub auth: String,
    pub channel: u32,
    pub connected: bool,
}

#[derive(Clone, Debug)]
pub struct BtRow {
    pub name: String,
    pub addr: String,
    pub kind: String,
    pub connected: bool,
    pub remembered: bool,
}

pub struct App {
    pub hwnd: isize,
    pub page: usize,
    pub now: u64,
    pub page_since: u64,
    pub started: Instant,

    pub hover: u32,
    pub pressed: u32,
    pub areas: Vec<(u32, Rect)>,
    pub hover_anim: HashMap<u32, Anim>,
    pub tab_anim: Anim,

    pub cidr: String,
    pub cidr_focus: bool,
    pub filter: String,
    pub filter_focus: bool,

    pub scanning: bool,
    pub capturing: bool,
    pub progress: (usize, usize),
    pub progress_shown: f32,
    pub scanned: usize,
    pub alive: usize,
    pub elapsed_ms: u128,
    pub kpi: [f32; 4],

    pub hosts: Vec<HostRow>,
    pub selected: Option<usize>,
    pub scroll: i32,

    pub packets: Vec<PktLine>,
    pub pkt_scroll: i32,
    pub cap_packets: u64,
    pub cap_bytes: u64,
    pub cap_tcp: u64,
    pub cap_udp: u64,
    pub row_flash: f32,
    pub save_pcap: bool,
    pub pcap_path: String,

    pub wifi: Vec<WifiRow>,
    pub wifi_err: String,
    pub wifi_loading: bool,
    pub bt: Vec<BtRow>,
    pub bt_radios: Vec<String>,
    pub bt_err: String,
    pub bt_loading: bool,
    pub sig_scroll: i32,

    pub status: String,
    pub status_kind: u8,
    pub status_since: u64,

    pub fonts: Fonts,
    pub rx: Receiver<UiEvent>,
    pub tx: Sender<UiEvent>,
    pub cancel: Option<Arc<AtomicBool>>,
    pub dirty: bool,
    pub caret_t: u64,
    pub my_ip: String,
    pub iface: String,
    pub npcap: bool,
    pub admin: bool,
    pub log: Vec<String>,
}

impl App {
    pub fn new(hwnd: isize, fonts: Fonts, tx: Sender<UiEvent>, rx: Receiver<UiEvent>) -> App {
        let (my_ip, iface, cidr) = match platform::default_net() {
            Some((net, i)) => (netradar_core::fmt_ip(i.ip), i.name.clone(), net.to_cidr()),
            None => (String::new(), String::new(), "192.168.1.0/24".to_string()),
        };
        App {
            hwnd,
            page: PAGE_SCAN,
            now: 0,
            page_since: 0,
            started: Instant::now(),
            hover: 0,
            pressed: 0,
            areas: Vec::new(),
            hover_anim: HashMap::new(),
            tab_anim: Anim::at(0.0),
            cidr,
            cidr_focus: false,
            filter: String::new(),
            filter_focus: false,
            scanning: false,
            capturing: false,
            progress: (0, 0),
            progress_shown: 0.0,
            scanned: 0,
            alive: 0,
            elapsed_ms: 0,
            kpi: [0.0; 4],
            hosts: Vec::new(),
            selected: None,
            scroll: 0,
            packets: Vec::new(),
            pkt_scroll: 0,
            cap_packets: 0,
            cap_bytes: 0,
            cap_tcp: 0,
            cap_udp: 0,
            row_flash: 0.0,
            save_pcap: true,
            pcap_path: String::new(),
            wifi: Vec::new(),
            wifi_err: String::new(),
            wifi_loading: false,
            bt: Vec::new(),
            bt_radios: Vec::new(),
            bt_err: String::new(),
            bt_loading: false,
            sig_scroll: 0,
            status: "就绪 · 输入网段后开始扫描".into(),
            status_kind: 0,
            status_since: 0,
            fonts,
            rx,
            tx,
            cancel: None,
            dirty: true,
            caret_t: 0,
            my_ip,
            iface,
            npcap: capture::npcap_available(),
            admin: platform::is_elevated(),
            log: Vec::new(),
        }
    }

    pub fn push_log(&mut self, s: String) {
        self.log.push(s);
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }

    pub fn set_status(&mut self, s: &str, kind: u8) {
        self.status = s.to_string();
        self.status_kind = kind;
        self.status_since = self.now;
        self.dirty = true;
    }

    pub fn area(&mut self, id: u32, r: Rect) {
        self.areas.push((id, r));
    }

    pub fn hit(&self, x: i32, y: i32) -> u32 {
        for (id, r) in self.areas.iter().rev() {
            if r.contains(x, y) {
                return *id;
            }
        }
        0
    }

    /* ---------------- 动画 ---------------- */

    pub fn change_page(&mut self, page: usize) {
        if self.page == page {
            return;
        }
        self.page = page;
        self.page_since = self.now;
        let target = page as f32;
        self.tab_anim.animate(target, self.now, 260, Curve::EaseOut);
        self.dirty = true;
    }

    /// 进入动画：(纵向偏移, 透明度)
    pub fn enter(&self, index: usize) -> (i32, u32) {
        let delay = index as u64 * 55;
        let t0 = self.page_since + delay;
        if self.now <= t0 {
            return (16, 0);
        }
        let t = ((self.now - t0) as f32 / 320.0).clamp(0.0, 1.0);
        let e = 1.0 - (1.0 - t) * (1.0 - t) * (1.0 - t);
        ((16.0 * (1.0 - e)) as i32, (255.0 * e) as u32)
    }

    pub fn hover_alpha(&self, id: u32) -> f32 {
        self.hover_anim
            .get(&id)
            .map(|a| a.value(self.now))
            .unwrap_or(0.0)
    }

    pub fn tick(&mut self, now: u64) {
        let dt = now.saturating_sub(self.now) as f32;
        self.now = now;
        self.caret_t = now;

        // 悬停渐变
        let hovered = self.hover;
        let ids: Vec<u32> = self.hover_anim.keys().copied().collect();
        for id in ids {
            let target = if id == hovered { 1.0 } else { 0.0 };
            if let Some(a) = self.hover_anim.get_mut(&id) {
                a.animate(target, now, 140, Curve::EaseOut);
            }
        }
        if hovered != 0 && !self.hover_anim.contains_key(&hovered) {
            let mut a = Anim::at(0.0);
            a.to = 1.0;
            a.start = now.saturating_sub(60);
            a.dur = 140;
            a.curve = Curve::EaseOut;
            self.hover_anim.insert(hovered, a);
        }
        // 回收
        self.hover_anim.retain(|_, a| {
            a.to > 0.01 || a.value(now) > 0.01 || a.active(now)
        });

        // 进度条平滑
        let target = if self.progress.1 == 0 {
            0.0
        } else {
            self.progress.0 as f32 / self.progress.1 as f32
        };
        self.progress_shown = chase(self.progress_shown, target, dt, 90.0);

        // KPI 数字滚动
        let ports: usize = self.hosts.iter().map(|h| h.ports.len()).sum();
        let targets = [
            self.scanned as f32,
            self.alive as f32,
            self.elapsed_ms as f32 / 1000.0,
            ports as f32,
        ];
        for i in 0..4 {
            self.kpi[i] = chase(self.kpi[i], targets[i], dt, 110.0);
        }

        // 新报文高亮衰减
        self.row_flash = chase(self.row_flash, 0.0, dt, 130.0);
    }

    pub fn needs_frame(&self) -> bool {
        if self.scanning || self.capturing || self.wifi_loading || self.bt_loading {
            return true;
        }
        if self.now.saturating_sub(self.page_since) < 800 {
            return true;
        }
        if self.row_flash > 0.02 {
            return true;
        }
        if self.tab_anim.active(self.now) {
            return true;
        }
        for a in self.hover_anim.values() {
            if a.active(self.now) {
                return true;
            }
        }
        false
    }

    /* ---------------- 扫描 ---------------- */

    pub fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        let net = match Net::parse(&self.cidr) {
            Ok(n) => n,
            Err(e) => {
                self.set_status(&format!("网段错误: {}", e), 3);
                return;
            }
        };
        if net.size() > 65536 {
            self.set_status("网段过大（上限 65536 个地址）", 3);
            return;
        }
        self.hosts.clear();
        self.selected = None;
        self.scroll = 0;
        self.scanned = net.hosts().count();
        self.alive = 0;
        self.elapsed_ms = 0;
        self.progress = (0, self.scanned);
        self.progress_shown = 0.0;
        self.scanning = true;
        self.started = Instant::now();
        self.set_status(&format!("正在扫描 {} …", net.to_cidr()), 0);

        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let tx = self.tx.clone();
        let opts = ScanOpts {
            timeout_ms: 500,
            threads: 256,
            ports: services::top_ports(),
            use_icmp: true,
            use_tcp: true,
            resolve_names: true,
            banner: true,
        };
        std::thread::spawn(move || {
            let mut cb = |ev: ScanEvent| {
                let _ = tx.send(UiEvent::Scan(ev));
            };
            scan::discover(net, &opts, &cancel, &mut cb);
        });
    }

    pub fn stop_scan(&mut self) {
        if let Some(c) = &self.cancel {
            c.store(true, Ordering::SeqCst);
        }
        self.scanning = false;
        self.set_status("已停止扫描", 2);
    }

    /* ---------------- 抓包 ---------------- */

    pub fn start_capture(&mut self) {
        if self.capturing {
            return;
        }
        if !self.npcap && !self.admin {
            self.set_status("抓包需要管理员权限（或安装 Npcap）", 3);
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.packets.clear();
        self.pkt_scroll = 0;
        self.cap_packets = 0;
        self.cap_bytes = 0;
        self.cap_tcp = 0;
        self.cap_udp = 0;
        self.capturing = true;
        let pcap = if self.save_pcap {
            let _ = std::fs::create_dir_all("captures");
            let ts = netradar_core::report::local_datetime()
                .replace('-', "")
                .replace(':', "")
                .replace(' ', "_");
            let p = format!("captures/netradar_{}.pcap", ts);
            self.pcap_path = p.clone();
            Some(p)
        } else {
            self.pcap_path.clear();
            None
        };
        let opts = CaptureOpts {
            iface: None,
            filter: Some(self.filter.clone()).filter(|f| !f.trim().is_empty()),
            count: 0,
            duration_ms: 0,
            pcap_out: pcap,
        };
        let tx = self.tx.clone();
        let tx2 = self.tx.clone();
        self.set_status("抓包中…", 1);
        std::thread::spawn(move || {
            let mut sink = |p: &netradar_core::capture::Packet| {
                let _ = tx.send(UiEvent::Packet(PktLine {
                    stamp: p.stamp.clone(),
                    proto: p.proto.to_string(),
                    src: p.src.clone(),
                    dst: p.dst.clone(),
                    info: p.info.clone(),
                }));
            };
            match capture::run(&opts, &cancel, &mut sink, false) {
                Ok(stats) => {
                    let _ = tx2.send(UiEvent::CapInfo(format!(
                        "__cap_stats__|{}|{}|{}|{}",
                        stats.tcp, stats.udp, stats.packets, stats.bytes
                    )));
                    let _ = tx2.send(UiEvent::CapDone(stats.packets, stats.bytes));
                }
                Err(e) => {
                    let _ = tx2.send(UiEvent::CapInfo(format!("__error__{}", e)));
                    let _ = tx2.send(UiEvent::CapDone(0, 0));
                }
            }
        });
    }

    pub fn stop_capture(&mut self) {
        if let Some(c) = &self.cancel {
            c.store(true, Ordering::SeqCst);
        }
        self.capturing = false;
        self.set_status("已停止抓包", 2);
    }

    /* ---------------- 信号扫描 ---------------- */

    pub fn start_signals(&mut self) {
        if self.wifi_loading || self.bt_loading {
            return;
        }
        self.wifi.clear();
        self.wifi_err.clear();
        self.bt.clear();
        self.bt_radios.clear();
        self.bt_err.clear();
        self.wifi_loading = true;
        self.bt_loading = true;
        self.set_status("正在扫描无线信号…", 0);
        let tx = self.tx.clone();
        let tx2 = self.tx.clone();
        std::thread::spawn(move || {
            let r = signals::wifi_scan(2200);
            let _ = tx.send(UiEvent::Wifi(r));
        });
        std::thread::spawn(move || {
            let r = signals::bt_scan(true, 4);
            let _ = tx2.send(UiEvent::Bt(r));
        });
    }

    /* ---------------- 事件泵 ---------------- */

    pub fn pump(&mut self) -> bool {
        let mut changed = false;
        loop {
            match self.rx.try_recv() {
                Ok(UiEvent::Scan(ev)) => {
                    changed = true;
                    match ev {
                        ScanEvent::Start { total, .. } => {
                            self.progress = (0, total);
                        }
                        ScanEvent::Progress { done, total } => {
                            self.progress = (done, total);
                        }
                        ScanEvent::HostUp(h) => {
                            self.alive += 1;
                            self.upsert(HostRow {
                                ip: h.ip_str(),
                                mac: if h.mac.is_some() { h.mac_str() } else { "-".into() },
                                vendor: h.vendor.clone().unwrap_or_default(),
                                name: h.hostname.clone().unwrap_or_default(),
                                method: h.method_str(),
                                rtt: h.rtt_ms.map(|v| v as i32).unwrap_or(-1),
                                ports: h.ports.iter().map(|p| p.port.to_string()).collect(),
                            });
                        }
                        ScanEvent::PortOpen { ip, port, .. } => {
                            let ip_s = netradar_core::fmt_ip(ip);
                            for h in self.hosts.iter_mut() {
                                if h.ip == ip_s && !h.ports.contains(&port.to_string()) {
                                    h.ports.push(port.to_string());
                                }
                            }
                        }
                        ScanEvent::PortProgress { done, total } => {
                            if total > 0 {
                                self.set_status(&format!("端口扫描 {}/{}", done, total), 0);
                            }
                        }
                        ScanEvent::Log(msg) => {
                            self.push_log(msg.clone());
                        }
                        ScanEvent::Done {
                            alive,
                            scanned,
                            elapsed_ms,
                        } => {
                            self.scanning = false;
                            self.alive = alive;
                            self.scanned = scanned;
                            self.elapsed_ms = elapsed_ms;
                            self.set_status(
                                &format!(
                                    "扫描完成 · 存活 {} 台 · 用时 {:.2}s",
                                    alive,
                                    elapsed_ms as f64 / 1000.0
                                ),
                                1,
                            );
                        }
                    }
                }
                Ok(UiEvent::Packet(p)) => {
                    changed = true;
                    self.cap_packets += 1;
                    if p.proto == "TCP" {
                        self.cap_tcp += 1;
                    } else if p.proto == "UDP" {
                        self.cap_udp += 1;
                    }
                    self.packets.push(p);
                    if self.packets.len() > 3000 {
                        self.packets.remove(0);
                    }
                    self.row_flash = 1.0;
                }
                Ok(UiEvent::CapInfo(s)) => {
                    changed = true;
                    if let Some(rest) = s.strip_prefix("__error__") {
                        self.set_status(&format!("抓包失败: {}", rest), 3);
                        self.capturing = false;
                    } else if let Some(rest) = s.strip_prefix("__cap_stats__|") {
                        let parts: Vec<&str> = rest.split('|').collect();
                        if parts.len() == 4 {
                            self.cap_tcp = parts[0].parse().unwrap_or(0);
                            self.cap_udp = parts[1].parse().unwrap_or(0);
                            self.cap_packets = parts[2].parse().unwrap_or(0);
                            self.cap_bytes = parts[3].parse().unwrap_or(0);
                        }
                    }
                }
                Ok(UiEvent::CapDone(pk, by)) => {
                    changed = true;
                    self.capturing = false;
                    if pk > 0 {
                        self.cap_packets = pk;
                        self.cap_bytes = by;
                        self.set_status(
                            &format!(
                                "抓包结束 · {} 个包 · {}",
                                pk,
                                if self.pcap_path.is_empty() {
                                    "未保存".to_string()
                                } else {
                                    self.pcap_path.clone()
                                }
                            ),
                            1,
                        );
                    }
                }
                Ok(UiEvent::Wifi(res)) => {
                    changed = true;
                    self.wifi_loading = false;
                    match res {
                        Ok(list) => {
                            self.wifi_err.clear();
                            self.wifi = list
                                .into_iter()
                                .map(|a| WifiRow {
                                    ssid: a.ssid,
                                    bssid: a.bssid,
                                    rssi: a.rssi,
                                    quality: a.quality,
                                    auth: a.auth,
                                    channel: a.channel,
                                    connected: a.connected,
                                })
                                .collect();
                            let n = self.wifi.len();
                            self.set_status(&format!("Wi-Fi: 发现 {} 个热点", n), 1);
                        }
                        Err(e) => {
                            self.wifi_err = e;
                            if self.wifi_err.starts_with("PERM|") {
                                self.set_status("Wi-Fi 需要定位权限（见信号页说明）", 2);
                            } else {
                                self.set_status(&format!("Wi-Fi: {}", self.wifi_err), 3);
                            }
                        }
                    }
                }
                Ok(UiEvent::Bt(res)) => {
                    changed = true;
                    self.bt_loading = false;
                    match res {
                        Ok((radios, devs)) => {
                            self.bt_err.clear();
                            self.bt_radios = radios.iter().map(|r| format!("{} ({})", r.name, r.addr)).collect();
                            self.bt = devs
                                .into_iter()
                                .map(|d| BtRow {
                                    name: d.name,
                                    addr: d.addr,
                                    kind: signals::bt_class_name(d.class).to_string(),
                                    connected: d.connected,
                                    remembered: d.remembered,
                                })
                                .collect();
                            let n = self.bt.len();
                            self.set_status(&format!("蓝牙: 发现 {} 个设备", n), 1);
                        }
                        Err(e) => {
                            self.bt_err = e;
                            self.set_status(&format!("蓝牙: {}", self.bt_err), 2);
                        }
                    }
                }
                Err(_) => break,
            }
        }
        if changed {
            self.dirty = true;
        }
        changed
    }

    fn upsert(&mut self, row: HostRow) {
        if let Some(h) = self.hosts.iter_mut().find(|h| h.ip == row.ip) {
            h.mac = row.mac;
            if !row.vendor.is_empty() {
                h.vendor = row.vendor;
            }
            if !row.name.is_empty() {
                h.name = row.name;
            }
            h.method = row.method;
            h.rtt = row.rtt;
            if !row.ports.is_empty() {
                h.ports = row.ports;
            }
        } else {
            self.hosts.push(row);
            self.hosts.sort_by_key(|h| ip_key(&h.ip));
            self.kpi[1] = self.hosts.len() as f32;
        }
    }
}

pub fn ip_key(ip: &str) -> u32 {
    let mut out: u32 = 0;
    for p in ip.split('.') {
        let v: u32 = p.parse().unwrap_or(0);
        out = (out << 8) | (v & 0xff);
    }
    out
}

pub fn make_channels() -> (Sender<UiEvent>, Receiver<UiEvent>) {
    channel()
}

pub type FontHandle = Gp;

pub const VERSION_STR: &str = VERSION;

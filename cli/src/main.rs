//! NetRadar 控制台前端（Windows exe / Android 原生命令行共用）
//!
//! 用法: netradar [选项]   不带参数进入交互模式

mod term;

use netradar_core::capture::{self, CaptureOpts};
use netradar_core::net::Net;
use netradar_core::platform;
use netradar_core::report::{self, Meta};
use netradar_core::scan::{self, ScanOpts};
use netradar_core::services;
use netradar_core::{fmt_ip, Host, ScanEvent, VERSION};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use term::Term;

/* ------------------------------- 结果缓存 ------------------------------- */

static LAST_RESULT: std::sync::OnceLock<std::sync::Mutex<Vec<Host>>> = std::sync::OnceLock::new();

fn store_last(hosts: &[Host], meta: &Meta) {
    let cell = LAST_RESULT.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    *cell.lock().unwrap() = hosts.to_vec();
    let m = LAST_META.get_or_init(|| std::sync::Mutex::new(Meta::default()));
    let mut guard = m.lock().unwrap();
    *guard = Meta {
        network: meta.network.clone(),
        scanned: meta.scanned,
        elapsed_ms: meta.elapsed_ms,
        iface: meta.iface.clone(),
        local_ip: meta.local_ip.clone(),
    };
}

static LAST_META: std::sync::OnceLock<std::sync::Mutex<Meta>> = std::sync::OnceLock::new();

fn take_last() -> (Vec<Host>, Meta) {
    let hosts = LAST_RESULT
        .get()
        .map(|m| m.lock().unwrap().clone())
        .unwrap_or_default();
    let meta = LAST_META
        .get()
        .map(|m| {
            let g = m.lock().unwrap();
            Meta {
                network: g.network.clone(),
                scanned: g.scanned,
                elapsed_ms: g.elapsed_ms,
                iface: g.iface.clone(),
                local_ip: g.local_ip.clone(),
            }
        })
        .unwrap_or_default();
    (hosts, meta)
}

/* ------------------------------- 参数解析 ------------------------------- */

#[derive(Clone, Default)]
pub struct Args {
    pub range: Option<String>,
    pub ports: Option<String>,
    pub scan_ip: Option<String>,
    pub capture: bool,
    pub capture_stdin: bool,
    pub filter: Option<String>,
    pub count: usize,
    pub duration: u64,
    pub pcap: Option<String>,
    pub iface: Option<u32>,
    pub json: Option<String>,
    pub csv: Option<String>,
    pub html: Option<String>,
    pub timeout: u64,
    pub threads: usize,
    pub quiet: bool,
    pub jsonl: bool,
    pub no_icmp: bool,
    pub no_tcp: bool,
    pub no_name: bool,
    pub list_ifaces: bool,
    pub list_devices: bool,
    pub signals: bool,
    pub no_color: bool,
    pub help: bool,
    pub version: bool,
    pub ping_ip: Option<String>,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut a = Args {
        timeout: 400,
        threads: 128,
        ..Default::default()
    };
    let mut i = 0usize;
    while i < raw.len() {
        let arg = raw[i].clone();
        let mut next_val = |i: &mut usize, name: &str| -> Result<String, String> {
            if let Some((_, v)) = arg.split_once('=') {
                return Ok(v.to_string());
            }
            *i += 1;
            raw.get(*i)
                .cloned()
                .ok_or_else(|| format!("参数 {} 缺少值", name))
        };
        match arg.split('=').next().unwrap_or("") {
            "-h" | "--help" => a.help = true,
            "-v" | "--version" => a.version = true,
            "-r" | "--range" | "--target" => a.range = Some(next_val(&mut i, "--range")?),
            "-p" | "--ports" => a.ports = Some(next_val(&mut i, "--ports")?),
            "-s" | "--scan" => a.scan_ip = Some(next_val(&mut i, "--scan")?),
            "--capture" | "-c" => a.capture = true,
            "--capture-stdin" => a.capture_stdin = true,
            "-f" | "--filter" => a.filter = Some(next_val(&mut i, "--filter")?),
            "-n" | "--count" => {
                a.count = next_val(&mut i, "--count")?.parse().unwrap_or(0);
            }
            "-d" | "--duration" => {
                a.duration = next_val(&mut i, "--duration")?.parse().unwrap_or(0);
            }
            "-w" | "--write" | "--pcap" => a.pcap = Some(next_val(&mut i, "--write")?),
            "-i" | "--iface" => {
                a.iface = next_val(&mut i, "--iface")?.parse().ok();
            }
            "--json" => a.json = Some(next_val(&mut i, "--json")?),
            "--csv" => a.csv = Some(next_val(&mut i, "--csv")?),
            "--html" => a.html = Some(next_val(&mut i, "--html")?),
            "--timeout" => {
                a.timeout = next_val(&mut i, "--timeout")?.parse().unwrap_or(400);
            }
            "--threads" | "-t" => {
                a.threads = next_val(&mut i, "--threads")?.parse().unwrap_or(128);
            }
            "--quiet" | "-q" => a.quiet = true,
            "--jsonl" => a.jsonl = true,
            "--no-icmp" => a.no_icmp = true,
            "--no-tcp" => a.no_tcp = true,
            "--no-name" => a.no_name = true,
            "--no-color" => a.no_color = true,
            "--list-ifaces" | "--ifaces" => a.list_ifaces = true,
            "--list-devices" => a.list_devices = true,
            "--signals" | "--wifi" | "--bt" => a.signals = true,
            "--ping" => a.ping_ip = Some(next_val(&mut i, "--ping")?),
            other => {
                if other.starts_with('-') {
                    return Err(format!("未知参数: {}", other));
                }
                a.range = Some(other.to_string());
            }
        }
        i += 1;
    }
    Ok(a)
}

/* ------------------------------- 静态图标 ------------------------------- */

const LOGO: &str = r"
  ███╗   ██╗███████╗████████╗██████╗  █████╗ ██████╗  █████╗ ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██████╔╝███████║██║  ██║███████║██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
  ██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝";

fn banner(t: &Term) {
    if t.color {
        println!("{}", t.paint(term::CYAN, LOGO));
    } else {
        println!("{}", LOGO);
    }
    let line = format!(
        "  网络发现 · 端口/指纹扫描 · 流量抓包     v{}  [Rust 引擎 / {} 位]",
        VERSION,
        std::mem::size_of::<usize>() * 8
    );
    println!("{}", t.paint(term::BOLD, &line));
    println!(
        "  {}\n",
        t.grey(&"─".repeat(term::width(&line).saturating_sub(4)))
    );
}

fn help(t: &Term) -> i32 {
    banner(t);
    let b = |s: &str| t.brcyan(s);
    println!("{}", t.bold("用法"));
    println!("  netradar.exe [选项]             执行一次扫描 / 抓包");
    println!("  netradar.exe                    进入交互模式\n");
    println!("{}", t.bold("扫描选项"));
    println!("  -r, --range <网段>    {} 例: 192.168.1.0/24 / 10.0.0.1-10.0.0.99", b("目标网段"));
    println!("  -p, --ports <端口>    例: 22,80,443 / 1-1024 / top100 / all");
    println!("  -s, --scan <IP>       对单个 IP 做全端口扫描 + 指纹识别");
    println!("      --timeout <ms>    探测超时 (默认 400)");
    println!("  -t, --threads <N>     并发线程 (默认 128)");
    println!("      --no-icmp         不发送 ICMP，只用 ARP/TCP 探测");
    println!("      --no-name         不做反向域名解析");
    println!("  -q, --quiet           只输出结果表格\n");
    println!("{}", t.bold("抓包选项"));
    println!("  -c, --capture         实时抓包 (Npcap 或系统 RAW SOCKET)");
    println!("  -f, --filter <表达式> tcp / udp / icmp / arp / host 1.2.3.4 / port 80");
    println!("  -n, --count <N>       抓够 N 个包后停止");
    println!("  -d, --duration <秒>   抓取时长");
    println!("  -w, --write <文件>    保存为 pcap（可直接用 Wireshark 打开）");
    println!("  -i, --iface <序号>    指定网卡（配合 --list-devices 查看）");
    println!("      --list-ifaces     列出本机网卡");
    println!("      --list-devices    列出可抓包设备\n");
    println!("{}", t.bold("导出"));
    println!("      --json <文件>     JSON 结果");
    println!("      --csv  <文件>     CSV 结果");
    println!("      --html <文件>     HTML 可视化报告");
    println!("      --jsonl           逐行 JSON 事件流（给 Android 前端用）\n");
    println!("{}", t.bold("示例"));
    println!("  netradar.exe -r 192.168.1.0/24 -p top100 --json out.json");
    println!("  netradar.exe -s 192.168.1.10 -p 1-1024");
    println!("  netradar.exe -c -f \"tcp port 443\" -n 50 -w https.pcap");
    println!();
    0
}

/* ------------------------------- 主流程 ------------------------------- */

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误: {}\n用 --help 查看用法", e);
            std::process::exit(2);
        }
    };
    let t = Term::new(args.no_color || args.jsonl);
    term::set_title("NetRadar — 网络发现器");
    let code = dispatch(&args, &t);
    if t.color {
        print!("{}", term::RESET);
    }
    std::process::exit(code);
}

fn dispatch(args: &Args, t: &Term) -> i32 {
    if args.help {
        return help(t);
    }
    if args.version {
        println!("NetRadar v{} (Rust {})", VERSION, "engine");
        return 0;
    }
    if args.list_ifaces {
        return cmd_list_ifaces(t);
    }
    if args.list_devices {
        return cmd_list_devices(t);
    }
    if args.signals {
        return cmd_signals(t);
    }
    if let Some(ip) = &args.ping_ip {
        return cmd_ping(t, ip);
    }
    if args.capture {
        return cmd_capture(args, t);
    }
    if args.capture_stdin {
        return cmd_capture_stdin(args);
    }
    if let Some(ip) = &args.scan_ip {
        return cmd_scan_single(args, t, ip);
    }
    if args.range.is_some() || args.ports.is_some() || args.json.is_some() || args.jsonl {
        return cmd_scan(args, t);
    }
    interactive(args, t)
}

fn cmd_list_ifaces(t: &Term) -> i32 {
    let ifs = platform::interfaces();
    if ifs.is_empty() {
        println!("{}", t.red("未发现可用网卡"));
        return 1;
    }
    println!("{}", t.bold("本机网卡"));
    let rows: Vec<Vec<String>> = ifs
        .iter()
        .map(|i| {
            vec![
                i.index.to_string(),
                i.name.clone(),
                i.cidr(),
                i.mac.clone().unwrap_or_else(|| "-".into()),
                i.gateway
                    .map(fmt_ip)
                    .unwrap_or_else(|| "-".into()),
                if i.is_default {
                    t.green("● 默认路由")
                } else {
                    "-".into()
                },
            ]
        })
        .collect();
    term::table(
        t,
        &["#", "网卡", "IPv4/掩码", "MAC", "网关", "状态"],
        &rows,
        true,
    );
    0
}

fn cmd_list_devices(t: &Term) -> i32 {
    let devs = capture::list_capture_devices();
    println!("{}", t.bold("可抓包设备"));
    for (i, d) in devs.iter().enumerate() {
        println!("  [{}] {}", i, d);
    }
    if capture::npcap_available() {
        println!("\n{}", t.green("检测到 Npcap，将使用它抓取以太网帧。"));
    } else {
        println!(
            "\n{}",
            t.yellow("未安装 Npcap，将退化为系统 RAW SOCKET（需管理员权限，仅 IP 层）。")
        );
    }
    0
}

fn cmd_ping(t: &Term, ip_str: &str) -> i32 {
    let ip = match netradar_core::parse_ip(ip_str) {
        Some(i) => i,
        None => {
            println!("{} 非法 IP: {}", t.red("!"), ip_str);
            return 2;
        }
    };
    println!("  {} {}", t.grey("ICMP 探测"), fmt_ip(ip));
    let ok = platform::ping(ip, 1200);
    let arp = platform::arp_table();
    println!(
        "  ICMP   : {}",
        match ok {
            Some(rtt) => t.green(&format!("可达, RTT {}ms", rtt)),
            None => t.yellow("无响应（可能被防火墙拦截，不代表主机不存在）"),
        }
    );
    println!(
        "  ARP 表 : {}",
        match arp.get(&ip) {
            Some(m) => t.green(m),
            None => t.grey("无记录"),
        }
    );
    let probe = scan::tcp_probe(ip, 80, 800);
    println!(
        "  TCP:80 : {:?}",
        match probe {
            scan::Probe::Open => t.green("开放"),
            scan::Probe::Closed => t.green("关闭但有 RST 响应（主机在线）"),
            scan::Probe::Filtered => t.yellow("超时/过滤"),
        }
    );
    0
}

fn cmd_signals(t: &Term) -> i32 {
    use netradar_core::signals;
    println!("{}", t.bold("无线信号扫描"));
    println!("  {} 正在扫描 Wi-Fi 热点…", t.grey("·"));
    match signals::wifi_scan(2200) {
        Ok(aps) => {
            if aps.is_empty() {
                println!("  {} 未发现 Wi-Fi 热点", t.yellow("!"));
            } else {
                println!("  {} 发现 {} 个热点", t.green("✔"), aps.len());
                let rows: Vec<Vec<String>> = aps
                    .iter()
                    .map(|a| {
                        let bars = bar_of(a.quality);
                        vec![
                            a.ssid.clone(),
                            format!("{} {}", bars, a.rssi),
                            a.bssid.clone(),
                            if a.channel > 0 { a.channel.to_string() } else { "-".into() },
                            a.auth.clone(),
                            a.cipher.clone(),
                            if a.connected { t.green("已连接").to_string() } else { "-".into() },
                        ]
                    })
                    .collect();
                term::table(
                    t,
                    &["SSID", "信号", "BSSID", "信道", "加密", "密码套件", "状态"],
                    &rows,
                    true,
                );
            }
        }
        Err(e) => println!("  {} Wi-Fi: {}", t.red("×"), e),
    }

    println!("\n  {} 正在扫描蓝牙设备（约 5 秒）…", t.grey("·"));
    println!("  {}", t.grey("注：Windows 经典蓝牙查询不返回 RSSI，仅已连接设备给出链路等级"));
    match signals::bt_scan(true, 4) {
        Ok((radios, devs)) => {
            for r in &radios {
                println!(
                    "  {} 适配器 {} ({})",
                    t.green("●"),
                    r.name,
                    r.addr
                );
            }
            if devs.is_empty() {
                println!("  {} 附近没有发现蓝牙设备", t.yellow("!"));
            } else {
                let rows: Vec<Vec<String>> = devs
                    .iter()
                    .map(|d| {
                        let sig = match signals::bt_link_hint(d.connected) {
                            Some(lv) => format!("{} 强", bar_of(lv as u32 * 20)),
                            None => "—".to_string(),
                        };
                        vec![
                            d.name.clone(),
                            d.addr.clone(),
                            signals::bt_class_name(d.class).to_string(),
                            sig,
                            if d.connected {
                                t.green("已连接").to_string()
                            } else if d.remembered {
                                "已配对".to_string()
                            } else {
                                "新发现".to_string()
                            },
                        ]
                    })
                    .collect();
                term::table(t, &["设备名", "地址", "类型", "信号", "状态"], &rows, true);
            }
        }
        Err(e) => println!("  {} 蓝牙: {}", t.red("×"), e),
    }
    0
}

fn bar_of(quality: u32) -> String {
    let n = (quality.min(100) / 20) as usize;
    let mut s = String::new();
    for i in 0..5 {
        s.push(if i < n { '▮' } else { '▯' });
    }
    s
}

fn build_scan_opts(args: &Args, ports: Vec<u16>) -> ScanOpts {
    ScanOpts {
        timeout_ms: args.timeout.max(20),
        threads: args.threads.clamp(1, 1024),
        ports,
        use_icmp: !args.no_icmp,
        use_tcp: !args.no_tcp,
        resolve_names: !args.no_name,
        banner: true,
    }
}

fn cmd_scan(args: &Args, t: &Term) -> i32 {
    let (net, iface_info) = match &args.range {
        Some(r) => match Net::parse(r) {
            Ok(n) => {
                // 尽量找到与该网段匹配的本机网卡（用于报告元信息）
                let ifs = platform::interfaces();
                let hit = ifs.into_iter().find(|i| {
                    let local = Net::new(i.ip, i.prefix);
                    local.contains(n.base) || n.contains(i.ip)
                });
                (n, hit)
            }
            Err(e) => {
                eprintln!("{} {}", t.red("网段解析失败:"), e);
                return 2;
            }
        },
        None => match platform::default_net() {
            Some((n, i)) => (n, Some(i)),
            None => {
                eprintln!(
                    "{}",
                    t.red("无法自动识别本机网段，请用 -r 指定，例如 -r 192.168.1.0/24")
                );
                return 2;
            }
        },
    };
    if net.size() > 65536 {
        eprintln!("{}", t.red("网段过大（>65536 地址），请改用更小的范围"));
        return 2;
    }
    let ports = match &args.ports {
        Some(s) => match services::parse_ports(s) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} {}", t.red("端口解析失败:"), e);
                return 2;
            }
        },
        None => Vec::new(),
    };
    let opts = build_scan_opts(args, ports);

    if !args.quiet && !args.jsonl {
        banner(t);
        println!("  {} {}", t.grey("目标网段"), t.brgreen(&net.to_cidr()));
        if let Some(i) = &iface_info {
            println!(
                "  {} {}  ({}, 网关 {})",
                t.grey("本机网卡"),
                i.name,
                i.cidr(),
                i.gateway.map(fmt_ip).unwrap_or_else(|| "-".into())
            );
        }
        println!(
            "  {} {}   {} {}ms   {} {}",
            t.grey("探测地址"),
            net.hosts().count(),
            t.grey("超时"),
            opts.timeout_ms,
            t.grey("线程"),
            opts.threads
        );
        if !opts.ports.is_empty() {
            println!(
                "  {} {} 个 {}",
                t.grey("端口"),
                opts.ports.len(),
                t.grey("(TCP connect)")
            );
        }
        println!();
    }

    let cancel = Arc::new(AtomicBool::new(false));
    install_ctrlc(cancel.clone());
    let mut renderer = Renderer::new(t, args);
    let start = std::time::Instant::now();
    let hosts = scan::discover(net, &opts, &cancel, &mut |ev| renderer.handle(&ev));
    let elapsed = start.elapsed().as_millis();

    if !args.jsonl {
        term::clear_line(t);
    }
    let meta = Meta {
        network: net.to_cidr(),
        scanned: net.hosts().count(),
        elapsed_ms: elapsed,
        iface: iface_info.as_ref().map(|i| i.name.clone()).unwrap_or_default(),
        local_ip: iface_info.as_ref().map(|i| fmt_ip(i.ip)).unwrap_or_default(),
    };
    if !args.jsonl {
        print_results(t, &hosts, &meta);
    }
    store_last(&hosts, &meta);
    export(args, t, &hosts, &meta);
    0
}

fn cmd_scan_single(args: &Args, t: &Term, ip_str: &str) -> i32 {
    let ip = match netradar_core::parse_ip(ip_str) {
        Some(i) => i,
        None => {
            eprintln!("{} {}", t.red("非法 IP:"), ip_str);
            return 2;
        }
    };
    let ports = match &args.ports {
        Some(s) => services::parse_ports(s).unwrap_or_default(),
        None => services::top_ports(),
    };
    let opts = build_scan_opts(args, ports.clone());
    if !args.quiet && !args.jsonl {
        banner(t);
        println!(
            "  {} {}    {} {} 个端口",
            t.grey("目标主机"),
            t.brgreen(&fmt_ip(ip)),
            t.grey("扫描"),
            ports.len()
        );
        println!();
    }
    let cancel = Arc::new(AtomicBool::new(false));
    install_ctrlc(cancel.clone());
    let mut renderer = Renderer::new(t, args);
    let host = scan::scan_single(ip, &ports, &opts, &cancel, &mut |ev| renderer.handle(&ev));
    if !args.jsonl {
        term::clear_line(t);
    }
    if !args.quiet && !args.jsonl {
        print_host_detail(t, &host);
    }
    let meta = Meta {
        network: format!("{}/32", fmt_ip(ip)),
        scanned: ports.len(),
        elapsed_ms: 0,
        iface: String::new(),
        local_ip: String::new(),
    };
    let hs = vec![host];
    export(args, t, &hs, &meta);
    0
}

fn export(args: &Args, t: &Term, hosts: &[Host], meta: &Meta) {
    if let Some(p) = &args.json {
        match report::write_file(p, &report::to_json(hosts, meta)) {
            Ok(_) => println!("{} JSON 已保存: {}", t.green("✔"), p),
            Err(e) => eprintln!("{}", t.red(&e)),
        }
    }
    if let Some(p) = &args.csv {
        match report::write_file(p, &report::to_csv(hosts)) {
            Ok(_) => println!("{} CSV 已保存: {}", t.green("✔"), p),
            Err(e) => eprintln!("{}", t.red(&e)),
        }
    }
    if let Some(p) = &args.html {
        match report::write_file(p, &report::to_html(hosts, meta)) {
            Ok(_) => println!("{} HTML 报告已保存: {}", t.green("✔"), p),
            Err(e) => eprintln!("{}", t.red(&e)),
        }
    }
}

/* ------------------------------- 输出渲染 ------------------------------- */

struct Renderer<'a> {
    t: &'a Term,
    quiet: bool,
    jsonl: bool,
    last_pct: usize,
    seen: usize,
}

impl<'a> Renderer<'a> {
    fn new(t: &'a Term, args: &Args) -> Self {
        Renderer {
            t,
            quiet: args.quiet,
            jsonl: args.jsonl,
            last_pct: 999,
            seen: 0,
        }
    }

    fn handle(&mut self, ev: &ScanEvent) {
        if self.jsonl {
            println!("{}", json_event(ev));
            return;
        }
        match ev {
            ScanEvent::Start { .. } => {}
            ScanEvent::Progress { done, total } => {
                if self.quiet {
                    return;
                }
                let pct = *done * 100 / (*total).max(1);
                let step = if self.t.tty { 1 } else { 10 };
                if pct / step != self.last_pct / step || *done == *total {
                    self.last_pct = pct;
                    term::progress(
                        self.t,
                        "扫描中",
                        *done,
                        *total,
                        &format!("已发现 {}", self.t.green(&self.seen.to_string())),
                    );
                }
            }
            ScanEvent::HostUp(h) => {
                self.seen += 1;
                if self.quiet {
                    return;
                }
                term::clear_line(self.t);
                let vendor = if h.vendor.is_some() {
                    self.t.magenta(&h.vendor_str())
                } else {
                    self.t.grey("-")
                };
                let name = match &h.hostname {
                    Some(n) => self.t.cyan(n),
                    None => String::new(),
                };
                let rtt = h
                    .rtt_ms
                    .map(|r| format!("{}ms", r))
                    .unwrap_or_else(|| "-".into());
                println!(
                    "  {} {:<15} {:<19} {:<16} {:<7} {} {}",
                    self.t.green("+"),
                    h.ip_str(),
                    h.mac_str(),
                    vendor,
                    rtt,
                    self.t.grey("["),
                    format!("{}{}", self.t.dim(&h.method_str()), self.t.grey("]"))
                );
                if !name.is_empty() {
                    println!("      {} {}", self.t.grey("└ 主机名"), name);
                }
            }
            ScanEvent::PortOpen { port, service, .. } => {
                if self.quiet {
                    return;
                }
                term::clear_line(self.t);
                println!(
                    "      {} {}{}",
                    self.t.grey("├"),
                    self.t.brgreen(&format!("{}/tcp", port)),
                    self.t.grey(&format!("  {}", service))
                );
            }
            ScanEvent::PortProgress { done, total } => {
                if self.quiet {
                    return;
                }
                term::progress(self.t, "端口扫描", *done, *total, "");
            }
            ScanEvent::Log(msg) => {
                if self.quiet {
                    return;
                }
                term::clear_line(self.t);
                println!("  {} {}", self.t.grey("·"), self.t.grey(msg));
            }
            ScanEvent::Done {
                alive,
                scanned,
                elapsed_ms,
            } => {
                if self.quiet {
                    return;
                }
                term::clear_line(self.t);
                println!(
                    "\n  {} 扫描完成: 存活 {} 台 / 探测 {} 个地址 / 用时 {:.2}s",
                    self.t.green("✔"),
                    self.t.brgreen(&alive.to_string()),
                    scanned,
                    *elapsed_ms as f64 / 1000.0
                );
            }
        }
        term::flush();
    }
}

fn json_esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

fn json_event(ev: &ScanEvent) -> String {
    match ev {
        ScanEvent::Start { net, total } => {
            format!("{{\"ev\":\"start\",\"net\":\"{}\",\"total\":{}}}", json_esc(net), total)
        }
        ScanEvent::Progress { done, total } => {
            format!("{{\"ev\":\"progress\",\"done\":{},\"total\":{}}}", done, total)
        }
        ScanEvent::HostUp(h) => format!(
            "{{\"ev\":\"host\",\"ip\":\"{}\",\"mac\":\"{}\",\"vendor\":\"{}\",\"hostname\":\"{}\",\"rtt\":{},\"method\":\"{}\"}}",
            h.ip_str(),
            h.mac_str(),
            json_esc(&h.vendor_str()),
            json_esc(h.hostname.as_deref().unwrap_or("")),
            h.rtt_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            h.method_str()
        ),
        ScanEvent::PortOpen { ip, port, service } => format!(
            "{{\"ev\":\"port\",\"ip\":\"{}\",\"port\":{},\"service\":\"{}\"}}",
            fmt_ip(*ip),
            port,
            json_esc(service)
        ),
        ScanEvent::PortProgress { done, total } => format!(
            "{{\"ev\":\"portprogress\",\"done\":{},\"total\":{}}}",
            done, total
        ),
        ScanEvent::Log(msg) => format!("{{\"ev\":\"log\",\"msg\":\"{}\"}}", json_esc(msg)),
        ScanEvent::Done {
            alive,
            scanned,
            elapsed_ms,
        } => format!(
            "{{\"ev\":\"done\",\"alive\":{},\"scanned\":{},\"elapsed_ms\":{}}}",
            alive, scanned, elapsed_ms
        ),
    }
}

fn print_results(t: &Term, hosts: &[Host], meta: &Meta) {
    if hosts.is_empty() {
        println!("\n{}", t.yellow(" 没有发现存活主机。"));
        println!(
            " {}",
            t.grey(" 提示: 目标网段是否正确？是否开启了防火墙？可尝试 -p 22,80,443 换探测端口。")
        );
        return;
    }
    println!("\n{}", t.bold(" 存活主机"));
    let rows: Vec<Vec<String>> = hosts
        .iter()
        .map(|h| {
            vec![
                t.brgreen(&h.ip_str()),
                h.mac_str(),
                if h.vendor.is_some() {
                    t.magenta(&h.vendor_str())
                } else {
                    t.grey("-")
                },
                h.hostname.clone().unwrap_or_else(|| t.grey("-")),
                h.rtt_ms
                    .map(|r| format!("{}ms", r))
                    .unwrap_or_else(|| "-".into()),
                t.dim(&h.method_str()),
                h.ports_str(),
            ]
        })
        .collect();
    term::table(
        t,
        &["IP 地址", "MAC 地址", "厂商", "主机名", "延迟", "探测", "端口"],
        &rows,
        true,
    );
    println!(
        "\n  {} 共 {} 台存活 · 探测 {} 个地址 · 用时 {:.2}s",
        t.green("✔"),
        hosts.len(),
        meta.scanned,
        meta.elapsed_ms as f64 / 1000.0
    );
}

fn print_host_detail(t: &Term, h: &Host) {
    println!("\n{}", t.bold(" 主机详情"));
    println!("  {:<10} {}", t.grey("IP"), t.brgreen(&h.ip_str()));
    println!("  {:<10} {}", t.grey("MAC"), h.mac_str());
    println!("  {:<10} {}", t.grey("厂商"), h.vendor_str());
    println!(
        "  {:<10} {}",
        t.grey("主机名"),
        h.hostname.clone().unwrap_or_else(|| "-".into())
    );
    println!("  {:<10} {}", t.grey("探测"), h.method_str());
    println!("  {:<10} {} 个", t.grey("开放端口"), h.ports.len());
    if !h.ports.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = h
            .ports
            .iter()
            .map(|p| {
                vec![
                    t.brgreen(&p.port.to_string()),
                    p.service.to_string(),
                    p.banner.clone().unwrap_or_else(|| t.grey("-")),
                ]
            })
            .collect();
        term::table(t, &["端口", "服务", "指纹"], &rows, true);
    }
    println!();
}

/* ------------------------------- 抓包 ------------------------------- */

fn cmd_capture(args: &Args, t: &Term) -> i32 {
    let opts = CaptureOpts {
        iface: args.iface,
        filter: args.filter.clone(),
        count: args.count,
        duration_ms: if args.duration > 0 {
            args.duration * 1000
        } else {
            0
        },
        pcap_out: args.pcap.clone(),
    };
    let admin = platform::is_elevated();
    println!();
    if !capture::npcap_available() && !admin {
        println!(
            "{}",
            t.red("  需要管理员权限：打开 RAW SOCKET 抓包必须提升权限。")
        );
        println!(" {}", t.grey(" 请右键“以管理员身份运行”，或安装 Npcap 后重试。"));
        return 3;
    }
    println!("  {} {}", t.grey("抓包后端"), if capture::npcap_available() { t.green("Npcap") } else { t.yellow("RAW SOCKET (IP 层)") });
    println!(
        "  {} {}",
        t.grey("过滤器  "),
        args.filter.clone().unwrap_or_else(|| "全部流量".into())
    );
    if let Some(p) = &args.pcap {
        println!("  {} {}", t.grey("保存到  "), p);
    }
    if args.count > 0 {
        println!("  {} {} 个包", t.grey("抓取上限"), args.count);
    }
    if args.duration > 0 {
        println!("  {} {} 秒", t.grey("持续时长"), args.duration);
    }
    println!("  {} {}", t.grey("提示    "), t.grey("Ctrl+C 停止"));
    let cancel = Arc::new(AtomicBool::new(true));
    cancel.store(false, Ordering::Relaxed);
    install_ctrlc(cancel.clone());
    println!();
    let start = std::time::Instant::now();
    match capture::run(&opts, &cancel, |_p| {}, true) {
        Ok(stats) => {
            println!();
            println!("{}", t.bold(" 抓包统计"));
            println!(
                "  {} TCP {} | UDP {} | ICMP {} | ARP {} | 其他 {}",
                t.grey("协议分布"),
                t.brgreen(&stats.tcp.to_string()),
                t.yellow(&stats.udp.to_string()),
                t.cyan(&stats.icmp.to_string()),
                t.magenta(&stats.arp.to_string()),
                stats.other
            );
            println!(
                "  {} {} 个包 / {} 字节 / {:.2}s",
                t.grey("总计    "),
                t.brgreen(&stats.packets.to_string()),
                stats.bytes,
                start.elapsed().as_secs_f64()
            );
            if let Some(p) = &stats.pcap_path {
                println!("  {} {}  {}", t.grey("pcap    "), p, t.green("(可用 Wireshark 打开)"));
            }
            0
        }
        Err(e) => {
            eprintln!("{} {}", t.red("抓包失败:"), e);
            3
        }
    }
}

fn cmd_capture_stdin(args: &Args) -> i32 {
    let opts = CaptureOpts {
        iface: None,
        filter: args.filter.clone(),
        count: args.count,
        duration_ms: args.duration * 1000,
        pcap_out: args.pcap.clone(),
    };
    let cancel = Arc::new(AtomicBool::new(false));
    match capture::run_stdin(&opts, &cancel, |_p| {}, true) {
        Ok(stats) => {
            eprintln!(
                "[netradar] capture done: {} packets, {} bytes",
                stats.packets, stats.bytes
            );
            0
        }
        Err(e) => {
            eprintln!("[netradar] capture error: {}", e);
            3
        }
    }
}

/* ------------------------------- Ctrl+C ------------------------------- */

static CTRL_C: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
fn install_ctrlc(cancel: Arc<AtomicBool>) {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    unsafe extern "system" fn handler(_code: u32) -> i32 {
        CTRL_C.store(true, Ordering::SeqCst);
        1
    }
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if !INSTALLED.swap(true, Ordering::SeqCst) {
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    }
    // 轮询线程：检测到 Ctrl+C 后置位 cancel
    std::thread::spawn(move || loop {
        if CTRL_C.load(Ordering::SeqCst) {
            eprintln!("\n[netradar] 收到中断信号，正在停止…");
            cancel.store(true, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(300));
            std::process::exit(130);
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    });
}

#[cfg(not(target_os = "windows"))]
fn install_ctrlc(_cancel: Arc<AtomicBool>) {}

/* ------------------------------- 交互模式 ------------------------------- */

fn interactive(base: &Args, t: &Term) -> i32 {
    banner(t);
    let ifs = platform::interfaces();
    if let Some(i) = ifs.first() {
        println!(
            "  {} {}   {} {}",
            t.grey("本机"),
            t.brgreen(&fmt_ip(i.ip)),
            t.grey("网卡"),
            i.name
        );
    }
    if let Some((net, _)) = platform::default_net() {
        println!("  {} {}", t.grey("自动网段"), t.brgreen(&net.to_cidr()));
    }
    if !capture::npcap_available() {
        println!(
            "  {}",
            t.grey("提示: 未检测到 Npcap，抓包将使用 RAW SOCKET（需管理员权限）")
        );
    }
    println!(
        "\n  {}  {}  {}  {}  {}  {}  {}",
        t.cyan("scan [网段]"),
        t.cyan("ports <IP> [端口]"),
        t.cyan("cap [过滤]"),
        t.cyan("ifaces"),
        t.cyan("export"),
        t.cyan("help"),
        t.cyan("quit")
    );
    println!();

    let mut last_meta = Meta::default();
    let _ = &mut last_meta;
    let stdin = std::io::stdin();
    loop {
        print!("  {} ", t.brcyan("netradar>"));
        term::flush();
        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("").to_ascii_lowercase();
        let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
        match cmd.as_str() {
            "q" | "quit" | "exit" => break,
            "help" | "?" => {
                println!("  scan [网段]        扫描网段（默认本机网段）");
                println!("  ports <IP> [端口]  单机端口扫描，端口默认 top100");
                println!("  cap [过滤表达式]   抓包，例如 cap tcp / cap port 443");
                println!("  ifaces             列出网卡");
                println!("  export [前缀]      导出上次结果为 html/json/csv");
                println!("  quit               退出");
            }
            "ifaces" | "if" => {
                cmd_list_ifaces(t);
            }
            "scan" | "s" => {
                let mut a = base.clone();
                a.range = rest.first().cloned();
                cmd_scan(&a, t);
            }
            "ports" | "p" => {
                if rest.is_empty() {
                    println!("  用法: ports <IP> [端口表达式]");
                    continue;
                }
                let mut a = base.clone();
                a.scan_ip = Some(rest[0].clone());
                if rest.len() > 1 {
                    a.ports = Some(rest[1].clone());
                }
                cmd_scan_single(&a, t, &rest[0]);
            }
            "cap" | "capture" => {
                let mut a = base.clone();
                a.capture = true;
                if !rest.is_empty() {
                    a.filter = Some(rest.join(" "));
                }
                if a.duration == 0 && a.count == 0 {
                    a.count = 0;
                    a.duration = 0;
                }
                cmd_capture(&a, t);
            }
            "export" => {
                let (last_hosts, last_meta) = take_last();
                if last_hosts.is_empty() {
                    println!("  {} 还没有扫描结果", t.yellow("!"));
                    continue;
                }
                let prefix = rest.first().cloned().unwrap_or_else(|| "netradar".into());
                let mut a = base.clone();
                a.html = Some(format!("{}.html", prefix));
                a.json = Some(format!("{}.json", prefix));
                a.csv = Some(format!("{}.csv", prefix));
                export(&a, t, &last_hosts, &last_meta);
            }
            other if other.starts_with("scan") => {}
            _ => {
                // 直接输入网段/CIDR 时按扫描处理
                if Net::parse(&line).is_ok() {
                    let mut a = base.clone();
                    a.range = Some(line.clone());
                    last_meta.network = line;
                    cmd_scan(&a, t);
                } else {
                    println!("  {} 未知命令: {} （输入 help 查看）", t.red("!"), line);
                }
            }
        }
    }
    println!("  再见。");
    0
}

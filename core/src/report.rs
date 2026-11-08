//! 结果导出：JSON / CSV / HTML 报告。

use crate::net::Net;
use crate::Host;

fn esc_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_os = "windows")]
pub fn local_datetime() -> String {
    #[repr(C)]
    struct St {
        year: u16,
        month: u16,
        dow: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        ms: u16,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocalTime(st: *mut St);
    }
    let mut st = St {
        year: 0,
        month: 0,
        dow: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        ms: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.year, st.month, st.day, st.hour, st.minute, st.second
    )
}

#[cfg(not(target_os = "windows"))]
pub fn local_datetime() -> String {
    let us = crate::capture::now_us();
    let secs = us / 1_000_000;
    let days = secs / 86400;
    let rem = secs % 86400;
    // 1970-01-01 起算
    let mut y = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let yd = if leap { 366 } else { 365 };
        if d >= yd {
            d -= yd;
            y += 1;
        } else {
            break;
        }
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mon = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    let mut dd = d;
    while m < 12 && dd >= mon[m] {
        dd -= mon[m];
        m += 1;
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m + 1,
        dd + 1,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

pub struct Meta {
    pub network: String,
    pub scanned: usize,
    pub elapsed_ms: u128,
    pub iface: String,
    pub local_ip: String,
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            network: String::new(),
            scanned: 0,
            elapsed_ms: 0,
            iface: String::new(),
            local_ip: String::new(),
        }
    }
}

pub fn to_json(hosts: &[Host], meta: &Meta) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"tool\": \"NetRadar\",\n"));
    out.push_str(&format!("  \"version\": \"{}\",\n", crate::VERSION));
    out.push_str(&format!(
        "  \"scan_time\": \"{}\",\n",
        esc_json(&local_datetime())
    ));
    out.push_str(&format!("  \"network\": \"{}\",\n", esc_json(&meta.network)));
    out.push_str(&format!("  \"iface\": \"{}\",\n", esc_json(&meta.iface)));
    out.push_str(&format!("  \"local_ip\": \"{}\",\n", esc_json(&meta.local_ip)));
    out.push_str(&format!("  \"scanned\": {},\n", meta.scanned));
    out.push_str(&format!("  \"alive\": {},\n", hosts.len()));
    out.push_str(&format!("  \"elapsed_ms\": {},\n", meta.elapsed_ms));
    out.push_str("  \"hosts\": [\n");
    for (i, h) in hosts.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"ip\": \"{}\",\n", h.ip_str()));
        out.push_str(&format!("      \"mac\": \"{}\",\n", esc_json(&h.mac_str())));
        out.push_str(&format!(
            "      \"vendor\": \"{}\",\n",
            esc_json(h.vendor.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "      \"hostname\": \"{}\",\n",
            esc_json(h.hostname.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "      \"rtt_ms\": {},\n",
            h.rtt_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
        ));
        out.push_str(&format!(
            "      \"methods\": [{}],\n",
            h.methods
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str("      \"ports\": [");
        if h.ports.is_empty() {
            out.push_str("]\n");
        } else {
            out.push('\n');
            for (j, p) in h.ports.iter().enumerate() {
                out.push_str(&format!(
                    "        {{\"port\": {}, \"service\": \"{}\", \"banner\": \"{}\"}}{}\n",
                    p.port,
                    esc_json(p.service),
                    esc_json(p.banner.as_deref().unwrap_or("")),
                    if j + 1 < h.ports.len() { "," } else { "" }
                ));
            }
            out.push_str("      ]\n");
        }
        out.push_str(&format!("    }}{}\n", if i + 1 < hosts.len() { "," } else { "" }));
    }
    out.push_str("  ]\n}\n");
    out
}

pub fn to_csv(hosts: &[Host]) -> String {
    let mut out = String::from("ip,mac,vendor,hostname,rtt_ms,methods,open_ports,banners\n");
    for h in hosts {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            h.ip_str(),
            h.mac_str(),
            csv_cell(&h.vendor_str()),
            csv_cell(h.hostname.as_deref().unwrap_or("")),
            h.rtt_ms.map(|v| v.to_string()).unwrap_or_default(),
            h.method_str(),
            csv_cell(&h.ports_str()),
            csv_cell(
                &h.ports
                    .iter()
                    .filter_map(|p| p.banner.clone())
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
        ));
    }
    out
}

fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn to_html(hosts: &[Host], meta: &Meta) -> String {
    let mut rows = String::new();
    for h in hosts {
        let ports = if h.ports.is_empty() {
            "<span style=\"color:#556\">-</span>".to_string()
        } else {
            h.ports
                .iter()
                .map(|p| {
                    let tip = esc_html(p.banner.as_deref().unwrap_or(""));
                    format!(
                        "<span class=\"port\" title=\"{}\">{}<i>{}</i></span>",
                        tip,
                        p.port,
                        if p.service == "unknown" { "" } else { p.service }
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        rows.push_str(&format!(
            "<tr><td class=\"ip\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>\n",
            h.ip_str(),
            esc_html(&h.mac_str()),
            esc_html(&h.vendor_str()),
            esc_html(h.hostname.as_deref().unwrap_or("-")),
            h.rtt_ms.map(|v| format!("{}ms", v)).unwrap_or_else(|| "-".into()),
            esc_html(&h.method_str()),
            ports
        ));
    }
    let title = format!("NetRadar 网络发现报告 — {}", meta.network);
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{title}</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2e;--line:#1e2a44;--txt:#dbe4f5;--dim:#7b8aa8;--acc:#22d3ee;--ok:#34d399}}
*{{box-sizing:border-box}}
body{{margin:0;background:linear-gradient(160deg,#080d18,#0b1020 60%,#101a30);color:var(--txt);font:14px/1.6 "Segoe UI",system-ui,"Microsoft YaHei",sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:32px 22px 60px}}
h1{{margin:0 0 6px;font-size:26px;letter-spacing:.5px;font-weight:650}}
h1 span{{color:var(--acc)}}
.sub{{color:var(--dim);margin-bottom:22px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px;min-width:132px}}
.card b{{display:block;font-size:22px;color:var(--acc);font-weight:600}}
.card i{{font-style:normal;color:var(--dim);font-size:12px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th{{text-align:left;padding:11px 12px;background:#16203a;color:#9fb2d4;font-size:12px;letter-spacing:.6px;text-transform:uppercase}}
td{{padding:10px 12px;border-top:1px solid var(--line);vertical-align:top}}
tr:hover td{{background:#16203a}}
.ip{{color:var(--ok);font-weight:600;font-family:Consolas,monospace}}
.mono{{font-family:Consolas,monospace;color:#9fb2d4}}
.port{{display:inline-block;background:#152a22;border:1px solid #1f4d3a;color:#7ef0b8;border-radius:6px;padding:1px 7px;margin:2px 3px 2px 0;font-family:Consolas,monospace;font-size:12px}}
.port i{{font-style:normal;color:#4d8a6d;margin-left:5px}}
footer{{margin-top:26px;color:#4b5a78;font-size:12px}}
</style></head><body><div class="wrap">
<h1>Net<span>Radar</span> 网络发现报告</h1>
<div class="sub">{net} · 扫描时间 {time} · 本机 {lip} · 网卡 {iface}</div>
<div class="cards">
<div class="card"><b>{alive}</b><i>存活主机</i></div>
<div class="card"><b>{scanned}</b><i>探测地址</i></div>
<div class="card"><b>{elapsed} ms</b><i>耗时</i></div>
<div class="card"><b>{ports}</b><i>开放端口</i></div>
</div>
<table><thead><tr><th>IP 地址</th><th>MAC</th><th>厂商</th><th>主机名</th><th>延迟</th><th>探测方式</th><th>开放端口</th></tr></thead>
<tbody>
{rows}</tbody></table>
<footer>Generated by NetRadar v{ver} · Rust 引擎 · {time}</footer>
</div></body></html>
"#,
        title = esc_html(&title),
        net = esc_html(&meta.network),
        time = esc_html(&local_datetime()),
        lip = esc_html(&meta.local_ip),
        iface = esc_html(&meta.iface),
        alive = hosts.len(),
        scanned = meta.scanned,
        elapsed = meta.elapsed_ms,
        ports = hosts.iter().map(|h| h.ports.len()).sum::<usize>(),
        rows = rows,
        ver = crate::VERSION
    )
}

pub fn write_file(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("写入 {} 失败: {}", path, e))
}

/// 便捷：把网段对象转成展示用字符串
pub fn net_label(net: &Net) -> String {
    net.to_cidr()
}

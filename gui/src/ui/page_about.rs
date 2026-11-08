//! 关于页

use super::*;
use netradar_core::VERSION;

pub fn draw(app: &mut App, p: &Painter, c: Rect) {
    let x0 = PAD;
    let w0 = c.w - PAD * 2;

    let (dy0, a0) = app.enter(0);
    let a0f = a0 as f32 / 255.0;
    let hero = Rect::new(x0, c.y + 18 + dy0, w0, 206);
    glass(p, hero, 20.0, a0f);

    // 顶部渐变带
    p.grad(
        Rect::new(hero.x + 1, hero.y + 1, hero.w - 2, 78),
        fade(0xFF22D3EE, 0.10 * a0f),
        fade(0xFF22D3EE, 0.0),
        false,
        19.0,
    );

    let cx = hero.x + 58;
    let cy = hero.y + 42;
    p.glow(cx, cy, 46, fade(ACCENT, 0.35 * a0f));
    p.circle(cx, cy, 22, fade(ACCENT, 0.14 * a0f));
    p.circle(cx, cy, 14, fade(ACCENT, 0.22 * a0f));
    p.circle(cx, cy, 4, fade(ACCENT, a0f));
    let ang = (app.now as f32 / 2600.0) * std::f32::consts::TAU;
    p.line(
        cx as f32,
        cy as f32,
        cx as f32 + ang.cos() * 20.0,
        cy as f32 + ang.sin() * 20.0,
        fade(ACCENT, 0.6 * a0f),
        1.6,
    );

    p.text("NetRadar", app.fonts.display, Rect::new(cx + 40, hero.y + 20, 320, 30), fade(TEXT, a0f), ALIGN_NEAR);
    p.text(
        &format!("v{}  ·  Rust 引擎 + 原生自绘界面", VERSION),
        app.fonts.small,
        Rect::new(cx + 40, hero.y + 52, 460, 20),
        fade(DIM, a0f),
        ALIGN_NEAR,
    );

    let feats = [
        ("主机发现", "ARP + ICMP + TCP 三重探测，ICMP 被屏蔽也能靠链路层判定", BLUE),
        ("端口指纹", "TCP connect 扫描 + banner 抓取，70 个常见端口指纹库", GREEN),
        ("流量抓包", "Npcap 优先，退化到 RAW SOCKET；BPF 风格过滤 + pcap 落盘", ACCENT),
        ("无线信号", "Wi-Fi 热点扫描与蓝牙设备发现（含查询模式）", PURPLE),
    ];
    let mut fy = hero.y + 96;
    for (title, desc, color) in feats {
        p.circle(hero.x + 28, fy + 9, 3, fade(color, a0f));
        p.text(title, app.fonts.body_b, Rect::new(hero.x + 40, fy - 2, 90, 22), fade(TEXT, a0f), ALIGN_NEAR);
        p.text(
            &fit(p, desc, app.fonts.small, hero.w - 180),
            app.fonts.small,
            Rect::new(hero.x + 136, fy, hero.w - 180, 22),
            fade(DIM, a0f),
            ALIGN_NEAR,
        );
        fy += 27;
    }

    // 下方两张卡
    let (dy1, a1) = app.enter(1);
    let a1f = a1 as f32 / 255.0;
    let top2 = hero.bottom() + 14 + dy1;
    let half = (w0 - 14) / 2;
    let keys = Rect::new(x0, top2, half, (c.bottom() - 16) - top2);
    let disc = Rect::new(x0 + half + 14, top2, half, (c.bottom() - 16) - top2);

    glass(p, keys, 18.0, a1f);
    p.text("快捷键", app.fonts.h2, Rect::new(keys.x + 18, keys.y + 13, 200, 24), fade(TEXT, a1f), ALIGN_NEAR);
    p.line(
        (keys.x + 18) as f32,
        (keys.y + 46) as f32,
        (keys.right() - 18) as f32,
        (keys.y + 46) as f32,
        fade(0xFFFFFF, 0.07 * a1f),
        1.0,
    );
    let list = [
        ("Enter", "开始扫描"),
        ("Ctrl+S", "开始 / 停止抓包"),
        ("Ctrl+E", "导出 HTML 报告"),
        ("Ctrl+1..4", "切换页面"),
        ("Esc", "取消输入焦点 / 取消选中"),
        ("滚轮", "滚动列表"),
    ];
    let mut y = keys.y + 60;
    for (k, d) in list {
        let kw = p.measure(k, app.fonts.tiny) + 18;
        let kr = Rect::new(keys.x + 18, y, kw, 22);
        p.round_rect(kr, 7.0, fade(0xFFFFFF, 0.08 * a1f));
        p.text_vcenter(k, app.fonts.tiny, kr, fade(ACCENT, a1f), ALIGN_CENTER);
        p.text_vcenter(d, app.fonts.small, Rect::new(kr.right() + 12, y, keys.w - 140, 22), fade(DIM, a1f), ALIGN_NEAR);
        y += 28;
    }

    glass(p, disc, 18.0, a1f);
    p.text("免责声明", app.fonts.h2, Rect::new(disc.x + 18, disc.y + 13, 200, 24), fade(AMBER, a1f), ALIGN_NEAR);
    p.line(
        (disc.x + 18) as f32,
        (disc.y + 46) as f32,
        (disc.right() - 18) as f32,
        (disc.y + 46) as f32,
        fade(0xFFFFFF, 0.07 * a1f),
        1.0,
    );
    let lines = [
        "本工具仅用于自有网络或已获授权网络的",
        "资产盘点、连通性排查与故障定位。",
        "",
        "未经授权对他人网络进行扫描、抓包或",
        "无线信号采集，可能违反当地法律法规，",
        "请自行承担使用责任。",
    ];
    let mut ly = disc.y + 62;
    for l in lines {
        p.text(l, app.fonts.small, Rect::new(disc.x + 18, ly, disc.w - 36, 22), fade(DIM, a1f), ALIGN_NEAR);
        ly += 24;
    }
}

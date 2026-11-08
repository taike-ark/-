//! 抓包页

use super::*;

pub fn draw(app: &mut App, p: &Painter, c: Rect) {
    let x0 = PAD;
    let w0 = c.w - PAD * 2;

    /* ---------- 过滤行 ---------- */
    let (dy0, a0) = app.enter(0);
    let a0f = a0 as f32 / 255.0;
    let top = Rect::new(x0, c.y + 18 + dy0, w0, 44);
    let cap_w = 116;
    let stop_w = 78;
    let cap_btn = Rect::new(top.right() - cap_w, top.y, cap_w, 44);
    let stop_btn = Rect::new(top.right() - cap_w - stop_w - 10, top.y, stop_w, 44);

    // 芯片
    let chips: [(&str, &str, u32, i32); 4] = [
        ("全部", "", ID_FILTER_ALL, 46),
        ("TCP", "tcp", ID_FILTER_TCP, 46),
        ("UDP", "udp", ID_FILTER_UDP, 46),
        ("ICMP", "icmp", ID_FILTER_ICMP, 54),
    ];
    let chips_w: i32 = chips.iter().map(|c| c.3).sum::<i32>() + 3 * 6;
    let chips_left = stop_btn.x - chips_w - 12;
    let mut chip_x = chips_left;
    for (label, expr, id, w) in chips {
        let r = Rect::new(chip_x, top.y + 8, w, 28);
        let on = app.filter == expr;
        button(app, p, id, r, label, Kind::Chip { on }, true, a0f);
        chip_x += w + 6;
    }

    let input = Rect::new(top.x, top.y, (chips_left - top.x - 12).max(160), 44);
    let filter = app.filter.clone();
    text_field(app, p, ID_FILTER, input, &filter, "过滤表达式：tcp port 443 / host 1.2.3.4", app.filter_focus, a0f);
    button(
        app,
        p,
        ID_CAP_START,
        cap_btn,
        if app.capturing { "抓包中…" } else { "开始抓包" },
        Kind::Primary,
        !app.capturing,
        a0f,
    );
    button(app, p, ID_CAP_STOP, stop_btn, "停止", Kind::Ghost, app.capturing, a0f);

    /* ---------- pcap 开关 ---------- */
    let (dy1, a1) = app.enter(1);
    let a1f = a1 as f32 / 255.0;
    let sy = top.bottom() + 12 + dy1;
    let toggle = Rect::new(x0, sy, 132, 22);
    app.area(ID_CAP_SAVE, toggle);
    let boxr = Rect::new(toggle.x, toggle.y + 3, 16, 16);
    if app.save_pcap {
        p.round_rect(boxr, 4.0, fade(ACCENT, a1f));
        p.line((boxr.x + 4) as f32, (boxr.y + 8) as f32, (boxr.x + 7) as f32, (boxr.y + 11) as f32, fade(0xFF04121F, a1f), 1.8);
        p.line((boxr.x + 7) as f32, (boxr.y + 11) as f32, (boxr.x + 12) as f32, (boxr.y + 5) as f32, fade(0xFF04121F, a1f), 1.8);
    } else {
        p.round_rect_stroke(boxr, 4.0, fade(0xFFFFFF, 0.18 * a1f), 1.0);
    }
    p.text_vcenter("保存 pcap 文件", app.fonts.small, Rect::new(toggle.x + 24, toggle.y, 130, 22), fade(DIM, a1f), ALIGN_NEAR);
    if !app.pcap_path.is_empty() {
        p.text(
            &fit(p, &format!("→ {}", app.pcap_path), app.fonts.tiny, w0 - 200),
            app.fonts.tiny,
            Rect::new(toggle.right() + 14, sy, w0 - 220, 22),
            fade(MUTED, a1f),
            ALIGN_NEAR,
        );
    }

    /* ---------- KPI ---------- */
    let (dy2, a2) = app.enter(2);
    let a2f = a2 as f32 / 255.0;
    let kp = Rect::new(x0, sy + 32 + dy2, w0, 92);
    let gap = 14;
    let kw = (w0 - gap * 3) / 4;
    let bytes = if app.cap_bytes > 1024 * 1024 {
        format!("{:.1}M", app.cap_bytes as f64 / 1048576.0)
    } else if app.cap_bytes > 1024 {
        format!("{:.1}K", app.cap_bytes as f64 / 1024.0)
    } else {
        format!("{}B", app.cap_bytes)
    };
    kpi_card(app, p, Rect::new(kp.x, kp.y, kw, kp.h), &app.cap_packets.to_string(), "数据包", ACCENT, a2f);
    kpi_card(app, p, Rect::new(kp.x + kw + gap, kp.y, kw, kp.h), &bytes, "流量", BLUE, a2f);
    kpi_card(app, p, Rect::new(kp.x + (kw + gap) * 2, kp.y, kw, kp.h), &app.cap_tcp.to_string(), "TCP", GREEN, a2f);
    kpi_card(app, p, Rect::new(kp.x + (kw + gap) * 3, kp.y, kw, kp.h), &app.cap_udp.to_string(), "UDP", PURPLE, a2f);

    /* ---------- 数据包列表 ---------- */
    let (dy3, a3) = app.enter(3);
    let a3f = a3 as f32 / 255.0;
    let list = Rect::new(x0, kp.bottom() + 16 + dy3, w0, (c.bottom() - 18) - (kp.bottom() + 16 + dy3));
    glass(p, list, 18.0, a3f);
    p.text("实时数据包", app.fonts.h2, Rect::new(list.x + 18, list.y + 13, 200, 24), fade(TEXT, a3f), ALIGN_NEAR);
    let hint = if app.npcap {
        "Npcap · 以太网帧"
    } else if app.admin {
        "RAW SOCKET · IP 层"
    } else {
        "需要管理员权限"
    };
    p.text(hint, app.fonts.tiny, Rect::new(list.right() - 220, list.y + 17, 200, 18), fade(MUTED, a3f), ALIGN_FAR);
    p.line(
        (list.x + 18) as f32,
        (list.y + 48) as f32,
        (list.right() - 18) as f32,
        (list.y + 48) as f32,
        fade(0xFFFFFF, 0.07 * a3f),
        1.0,
    );

    let ltop = list.y + 58;
    let lbot = list.bottom() - 12;
    let line_h = 23;
    let visible = ((lbot - ltop) / line_h).max(1) as usize;
    let total = app.packets.len();
    let max_scroll = total.saturating_sub(visible) as i32;
    app.pkt_scroll = app.pkt_scroll.clamp(0, max_scroll);

    if total == 0 {
        p.text(
            "点击「开始抓包」后，这里会实时滚动显示解析结果",
            app.fonts.small,
            Rect::new(list.x, (ltop + lbot) / 2 - 10, list.w, 22),
            fade(MUTED, a3f),
            ALIGN_CENTER,
        );
        if !app.npcap && !app.admin {
            p.text(
                "提示：抓包需要管理员权限，右键「以管理员身份运行」",
                app.fonts.tiny,
                Rect::new(list.x, (ltop + lbot) / 2 + 16, list.w, 20),
                fade(AMBER, 0.75 * a3f),
                ALIGN_CENTER,
            );
        }
        return;
    }

    // 列位置
    let usable = list.w - 36;
    let stamp_w = 92;
    let proto_w = 44;
    let arrow_w = 16;
    let rest = usable - stamp_w - proto_w - arrow_w - 46;
    let (src_w, dst_w, info_w) = if rest >= 560 {
        let half = (rest - 230) / 2;
        (half, half, 230)
    } else if rest >= 300 {
        let half = rest / 2;
        (half, half, 0)
    } else {
        (rest / 2, rest / 2, 0)
    };
    let x_stamp = list.x + 18;
    let x_proto = x_stamp + stamp_w;
    let x_src = x_proto + proto_w + 6;
    let x_arrow = x_src + src_w + 6;
    let x_dst = x_arrow + arrow_w + 6;
    let x_info = x_dst + dst_w + 10;

    p.clip(Rect::new(list.x + 4, ltop - 4, list.w - 8, lbot - ltop + 8));
    let start = total.saturating_sub(visible + app.pkt_scroll as usize);
    let mut y = ltop;
    for (n, pkt) in app.packets.iter().skip(start).take(visible).enumerate() {
        let is_last = start + n + 1 == total && app.row_flash > 0.02;
        if is_last {
            p.round_rect(
                Rect::new(list.x + 8, y, list.w - 16, line_h),
                8.0,
                fade(ACCENT, 0.18 * app.row_flash),
            );
        }
        let proto_c = match pkt.proto.as_str() {
            "TCP" => GREEN,
            "UDP" => BLUE,
            "ICMP" => AMBER,
            "ARP" => PURPLE,
            _ => DIM,
        };
        p.text(&pkt.stamp, app.fonts.mono, Rect::new(x_stamp, y, stamp_w, line_h), fade(0xFF4D6A8A, a3f), ALIGN_NEAR);
        p.text(&pkt.proto, app.fonts.mono, Rect::new(x_proto, y, proto_w, line_h), fade(proto_c, a3f), ALIGN_NEAR);
        p.text(
            &fit(p, &pkt.src, app.fonts.mono, src_w - 4),
            app.fonts.mono,
            Rect::new(x_src, y, src_w, line_h),
            fade(TEXT, a3f),
            ALIGN_NEAR,
        );
        p.text("→", app.fonts.mono, Rect::new(x_arrow, y, arrow_w, line_h), fade(MUTED, a3f), ALIGN_NEAR);
        p.text(
            &fit(p, &pkt.dst, app.fonts.mono, dst_w - 4),
            app.fonts.mono,
            Rect::new(x_dst, y, dst_w, line_h),
            fade(TEXT, a3f),
            ALIGN_NEAR,
        );
        if info_w > 0 {
            p.text(
                &fit(p, &pkt.info, app.fonts.mono, info_w),
                app.fonts.mono,
                Rect::new(x_info, y, info_w, line_h),
                fade(DIM, a3f),
                ALIGN_NEAR,
            );
        }
        y += line_h;
    }
    p.unclip();
}

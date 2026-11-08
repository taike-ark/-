//! 扫描页

use super::*;

pub fn draw(app: &mut App, p: &Painter, c: Rect) {
    let x0 = PAD;
    let w0 = c.w - PAD * 2;

    /* ---------- 目标行 ---------- */
    let (dy0, a0) = app.enter(0);
    let top = Rect::new(x0, c.y + 18 + dy0, w0, 44);
    let start_w = 116;
    let stop_w = 78;
    let start = Rect::new(top.right() - start_w, top.y, start_w, 44);
    let stop = Rect::new(top.right() - start_w - stop_w - 10, top.y, stop_w, 44);
    let input = Rect::new(top.x + 78, top.y, 360.min(top.w - start_w - stop_w - 130), 44);

    p.text_vcenter("目标网段", app.fonts.small, Rect::new(top.x, top.y, 70, 44), fade(DIM, a0 as f32 / 255.0), ALIGN_NEAR);
    let cidr = app.cidr.clone();
    text_field(app, p, ID_CIDR, input, &cidr, "输入网段，如 192.168.1.0/24", app.cidr_focus, a0 as f32 / 255.0);
    button(
        app,
        p,
        ID_SCAN_START,
        start,
        if app.scanning { "扫描中…" } else { "开始扫描" },
        Kind::Primary,
        !app.scanning,
        a0 as f32 / 255.0,
    );
    button(app, p, ID_SCAN_STOP, stop, "停止", Kind::Ghost, app.scanning, a0 as f32 / 255.0);

    /* ---------- KPI ---------- */
    let (dy1, a1) = app.enter(1);
    let kp = Rect::new(x0, top.bottom() + 16 + dy1, w0, 92);
    let gap = 14;
    let kw = (w0 - gap * 3) / 4;
    let a1f = a1 as f32 / 255.0;
    let ports: usize = app.hosts.iter().map(|h| h.ports.len()).sum();
    let vals = [
        format!("{}", app.kpi[0].round() as usize),
        format!("{}", app.kpi[1].round() as usize),
        format!("{:.1}s", app.kpi[2]),
        format!("{}", app.kpi[3].round() as usize),
    ];
    kpi_card(app, p, Rect::new(kp.x, kp.y, kw, kp.h), &vals[0], "探测地址", BLUE, a1f);
    kpi_card(app, p, Rect::new(kp.x + kw + gap, kp.y, kw, kp.h), &vals[1], "存活主机", GREEN, a1f);
    kpi_card(app, p, Rect::new(kp.x + (kw + gap) * 2, kp.y, kw, kp.h), &vals[2], "耗时", ACCENT, a1f);
    kpi_card(app, p, Rect::new(kp.x + (kw + gap) * 3, kp.y, kw, kp.h), &vals[3], "开放端口", PURPLE, a1f);
    let _ = ports;

    /* ---------- 进度 ---------- */
    let mut table_y = kp.bottom() + 16;
    if app.scanning || app.progress_shown > 0.01 {
        let (dy2, a2) = app.enter(2);
        let a2f = a2 as f32 / 255.0;
        let label_y = kp.bottom() + 12 + dy2;
        p.text(
            &format!(
                "{} / {} · {:.0}%",
                app.progress.0,
                app.progress.1,
                app.progress_shown * 100.0
            ),
            app.fonts.tiny,
            Rect::new(x0, label_y, 300, 16),
            fade(MUTED, a2f),
            ALIGN_NEAR,
        );
        let track = Rect::new(x0, label_y + 21, w0, 6);
        p.round_rect(track, 3.0, fade(0xFFFFFF, 0.08 * a2f));
        let fw = (w0 as f32 * app.progress_shown) as i32;
        if fw > 3 {
            let fill = Rect::new(x0, track.y, fw, 6);
            p.grad(fill, fade(ACCENT, a2f), fade(GREEN, a2f), true, 3.0);
        }
        table_y = track.bottom() + 14;
    }

    /* ---------- 主机表 ---------- */
    let (dy3, a3) = app.enter(3);
    let a3f = a3 as f32 / 255.0;
    let table = Rect::new(x0, table_y + dy3, w0, (c.bottom() - 18) - (table_y + dy3));
    glass(p, table, 18.0, a3f);

    // 卡片头
    p.text(
        "主机列表",
        app.fonts.h2,
        Rect::new(table.x + 18, table.y + 13, 200, 24),
        fade(TEXT, a3f),
        ALIGN_NEAR,
    );
    let count = format!("{} 台", app.hosts.len());
    let mut bx = table.right() - 16;
    for (id, label) in [
        (ID_EXPORT_HTML, "HTML"),
        (ID_EXPORT_CSV, "CSV"),
        (ID_EXPORT_JSON, "JSON"),
    ] {
        let bw = 54;
        bx -= bw;
        button(
            app,
            p,
            id,
            Rect::new(bx, table.y + 11, bw, 26),
            label,
            Kind::Chip { on: false },
            !app.hosts.is_empty(),
            a3f,
        );
        bx -= 6;
    }
    let cw = p.measure(&count, app.fonts.tiny);
    p.text(
        &count,
        app.fonts.tiny,
        Rect::new(bx - cw - 12, table.y + 15, cw, 18),
        fade(DIM, a3f),
        ALIGN_NEAR,
    );
    p.line(
        (table.x + 18) as f32,
        (table.y + 48) as f32,
        (table.right() - 18) as f32,
        (table.y + 48) as f32,
        fade(0xFFFFFF, 0.07 * a3f),
        1.0,
    );

    // 列宽
    let avail = table.w - 40;
    let w_ip = (avail as f32 * 0.15) as i32;
    let w_mac = (avail as f32 * 0.17) as i32;
    let w_ven = (avail as f32 * 0.15) as i32;
    let w_name = (avail as f32 * 0.17) as i32;
    let w_rtt = (avail as f32 * 0.075) as i32;
    let w_meth = (avail as f32 * 0.09) as i32;
    let w_port = avail - w_ip - w_mac - w_ven - w_name - w_rtt - w_meth;
    let cols: [(&str, i32); 7] = [
        ("IP 地址", w_ip),
        ("MAC 地址", w_mac),
        ("厂商", w_ven),
        ("主机名", w_name),
        ("延迟", w_rtt),
        ("探测", w_meth),
        ("开放端口", w_port),
    ];
    let mut cx = table.x + 20;
    let hy = table.y + 54;
    let mut col_x: Vec<i32> = Vec::new();
    for (name, cw) in cols {
        col_x.push(cx);
        p.text(name, app.fonts.tiny, Rect::new(cx, hy, cw, 20), fade(MUTED, a3f), ALIGN_NEAR);
        cx += cw;
    }

    let list_top = table.y + 78;
    let list_bot = table.bottom() - 12;
    let row_h = 40;
    let visible = ((list_bot - list_top) / row_h).max(0);
    let max_scroll = (app.hosts.len() as i32 - visible).max(0) * row_h;
    app.scroll = app.scroll.clamp(0, max_scroll.max(0));

    if app.hosts.is_empty() {
        let cx = table.x + table.w / 2;
        let cy = list_top + (list_bot - list_top) / 2 - 8;
        let sweep = (app.now as f32 / 1400.0) % 1.0;
        for i in 1..=3 {
            let r = 18 * i;
            p.round_rect_stroke(
                Rect::new(cx - r, cy - r, r * 2, r * 2),
                r as f32,
                fade(ACCENT, 0.12 * a3f),
                1.2,
            );
        }
        let ang = sweep * std::f32::consts::TAU;
        p.line(
            cx as f32,
            cy as f32,
            cx as f32 + ang.cos() * 54.0,
            cy as f32 + ang.sin() * 54.0,
            fade(ACCENT, 0.45 * a3f),
            1.6,
        );
        p.circle(cx, cy, 4, fade(ACCENT, 0.9 * a3f));
        p.text(
            if app.scanning { "正在探测…" } else { "暂无数据" },
            app.fonts.h2,
            Rect::new(table.x, cy + 64, table.w, 26),
            fade(DIM, a3f),
            ALIGN_CENTER,
        );
        p.text(
            "输入网段后点击「开始扫描」，或按 Enter",
            app.fonts.small,
            Rect::new(table.x, cy + 92, table.w, 22),
            fade(MUTED, a3f),
            ALIGN_CENTER,
        );
        return;
    }

    p.clip(Rect::new(table.x + 4, list_top - 6, table.w - 8, list_bot - list_top + 6));
    let skip = (app.scroll / row_h) as usize;
    let mut y = list_top - (app.scroll % row_h);
    let (mx, my) = mouse();
    let total = app.hosts.len();
    for i in skip..total {
        if y > list_bot {
            break;
        }
        let h = app.hosts[i].clone();
        let row = Rect::new(table.x + 10, y, table.w - 20, row_h - 4);
        let sel = app.selected == Some(i);
        let row_hot = row.contains(mx, my);
        if sel {
            p.round_rect(row, 10.0, fade(ACCENT, 0.14 * a3f));
            p.round_rect_stroke(row, 10.0, fade(ACCENT, 0.35 * a3f), 1.0);
            p.round_rect(Rect::new(row.x, row.y + 9, 3, row.h - 18), 1.5, fade(ACCENT, a3f));
        } else if row_hot {
            p.round_rect(row, 10.0, fade(0xFFFFFF, 0.05 * a3f));
        }
        let ip_c = if sel { ACCENT } else { 0xFF7EF0B8 };
        p.text_vcenter(&h.ip, app.fonts.body_b, Rect::new(col_x[0], y, cols[0].1, row_h), fade(ip_c, a3f), ALIGN_NEAR);
        p.text_vcenter(
            &h.mac,
            app.fonts.small,
            Rect::new(col_x[1], y, cols[1].1, row_h),
            fade(if h.mac == "-" { MUTED } else { DIM }, a3f),
            ALIGN_NEAR,
        );
        p.text_vcenter(
            if h.vendor.is_empty() { "-" } else { &h.vendor },
            app.fonts.small,
            Rect::new(col_x[2], y, cols[2].1, row_h),
            fade(if h.vendor.is_empty() { MUTED } else { PURPLE }, a3f),
            ALIGN_NEAR,
        );
        let name = if h.name.is_empty() { "-".to_string() } else { h.name.clone() };
        p.text_vcenter(
            &fit(p, &name, app.fonts.small, cols[3].1 - 8),
            app.fonts.small,
            Rect::new(col_x[3], y, cols[3].1, row_h),
            fade(if h.name.is_empty() { MUTED } else { DIM }, a3f),
            ALIGN_NEAR,
        );
        p.text_vcenter(
            &if h.rtt >= 0 { format!("{}ms", h.rtt) } else { "-".into() },
            app.fonts.small,
            Rect::new(col_x[4], y, cols[4].1, row_h),
            fade(DIM, a3f),
            ALIGN_NEAR,
        );
        p.text_vcenter(&h.method, app.fonts.tiny, Rect::new(col_x[5], y, cols[5].1, row_h), fade(MUTED, a3f), ALIGN_NEAR);

        let mut px = col_x[6];
        let limit = table.right() - 26;
        let mut shown = 0usize;
        for port in h.ports.iter() {
            let wpx = p.measure(port, app.fonts.tiny) + 13;
            if px + wpx > limit {
                p.text(
                    &format!("+{}", h.ports.len() - shown),
                    app.fonts.tiny,
                    Rect::new(px, y, 30, row_h),
                    fade(MUTED, a3f),
                    ALIGN_NEAR,
                );
                break;
            }
            let pr = Rect::new(px, y + (row_h - 19) / 2, wpx, 19);
            p.round_rect(pr, 6.0, fade(0xFF34D399, 0.13 * a3f));
            p.text_vcenter(port, app.fonts.tiny, pr, fade(0xFF7EF0B8, a3f), ALIGN_CENTER);
            px += wpx + 5;
            shown += 1;
        }
        if h.ports.is_empty() {
            p.text("-", app.fonts.tiny, Rect::new(col_x[6], y, 40, row_h), fade(MUTED, a3f), ALIGN_NEAR);
        }
        app.area(1000 + i as u32, row);
        y += row_h;
    }
    p.unclip();

    // 滚动条
    if total as i32 > visible && visible > 0 {
        let track = Rect::new(table.right() - 8, list_top, 3, list_bot - list_top);
        p.round_rect(track, 1.5, fade(0xFFFFFF, 0.08 * a3f));
        let ratio = visible as f32 / total as f32;
        let thumb_h = ((list_bot - list_top) as f32 * ratio).max(26.0) as i32;
        let maxs = (total as i32 - visible).max(1) as f32;
        let prop = app.scroll as f32 / (maxs * row_h as f32);
        let ty = list_top + ((list_bot - list_top - thumb_h) as f32 * prop) as i32;
        p.round_rect(Rect::new(track.x, ty, 3, thumb_h), 1.5, fade(ACCENT, 0.55 * a3f));
    }
}

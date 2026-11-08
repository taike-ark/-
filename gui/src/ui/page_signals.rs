//! 无线信号页：Wi-Fi 热点 + 蓝牙设备

use super::*;

fn bars(p: &Painter, x: i32, y: i32, level: u8, alpha: f32) {
    let filled = level.min(4) as usize + 1;
    for i in 0..5usize {
        let h = 4 + i as i32 * 3;
        let r = Rect::new(x + i as i32 * 5, y + (16 - h), 3, h);
        let c = if i < filled {
            fade(if filled >= 4 { GREEN } else { AMBER }, alpha)
        } else {
            fade(0xFFFFFF, 0.12 * alpha)
        };
        p.round_rect(r, 1.5, c);
    }
}

fn section(
    app: &mut App,
    p: &Painter,
    r: Rect,
    title: &str,
    sub: &str,
    alpha: f32,
) {
    glass(p, r, 18.0, alpha);
    p.text(title, app.fonts.h2, Rect::new(r.x + 18, r.y + 13, 220, 24), fade(TEXT, alpha), ALIGN_NEAR);
    if !sub.is_empty() {
        p.text(
            sub,
            app.fonts.tiny,
            Rect::new(r.x + 18 + p.measure(title, app.fonts.h2) + 10, r.y + 18, r.w - 260, 18),
            fade(MUTED, alpha),
            ALIGN_NEAR,
        );
    }
    p.line(
        (r.x + 18) as f32,
        (r.y + 46) as f32,
        (r.right() - 18) as f32,
        (r.y + 46) as f32,
        fade(0xFFFFFF, 0.07 * alpha),
        1.0,
    );
}

pub fn draw(app: &mut App, p: &Painter, c: Rect) {
    let x0 = PAD;
    let w0 = c.w - PAD * 2;

    /* ---------- 操作行 ---------- */
    let (dy0, a0) = app.enter(0);
    let a0f = a0 as f32 / 255.0;
    let top = Rect::new(x0, c.y + 18 + dy0, w0, 44);
    let btn = Rect::new(top.x, top.y, 132, 44);
    let busy = app.wifi_loading || app.bt_loading;
    button(
        app,
        p,
        ID_SIG_REFRESH,
        btn,
        if busy { "扫描中…" } else { "扫描无线信号" },
        Kind::Primary,
        !busy,
        a0f,
    );
    let wifi_n = app.wifi.len();
    let bt_n = app.bt.len();
    p.text_vcenter(
        &format!("Wi-Fi {} 个热点 · 蓝牙 {} 个设备", wifi_n, bt_n),
        app.fonts.small,
        Rect::new(btn.right() + 16, top.y, 360, 44),
        fade(DIM, a0f),
        ALIGN_NEAR,
    );
    if busy {
        let pulse = 0.5 + 0.5 * ((app.now as f32 / 380.0).sin());
        p.circle(top.right() - 140, top.y + 22, 3, fade(ACCENT, 0.4 + 0.6 * pulse));
        p.text_vcenter(
            "正在采集信号…",
            app.fonts.small,
            Rect::new(top.right() - 128, top.y, 130, 44),
            fade(ACCENT, a0f),
            ALIGN_NEAR,
        );
    }

    /* ---------- 两张卡片 ---------- */
    let (dy1, a1) = app.enter(1);
    let (dy2, a2) = app.enter(2);
    let a1f = a1 as f32 / 255.0;
    let a2f = a2 as f32 / 255.0;
    let cards_top = top.bottom() + 16;
    let avail = (c.bottom() - 18) - cards_top;
    let perm0 = app.wifi_err.starts_with("PERM|");
    let compact = perm0
        || !app.wifi_err.is_empty()
        || (app.wifi.is_empty() && !app.wifi_loading);
    let h1 = if compact { 186 } else { (avail as f32 * 0.46) as i32 };
    let wifi_card = Rect::new(x0, cards_top + dy1, w0, h1);
    let bt_card = Rect::new(x0, cards_top + h1 + 14 + dy2, w0, avail - h1 - 14);

    /* Wi-Fi */
    let perm = app.wifi_err.starts_with("PERM|");
    let sub = if perm {
        "需要定位权限"
    } else if !app.wifi_err.is_empty() {
        "不可用"
    } else {
        ""
    };
    section(app, p, wifi_card, "Wi-Fi 热点", sub, a1f);

    if perm || (app.wifi_err.is_empty() && app.wifi.is_empty() && !app.wifi_loading) {
        let msg = if perm {
            "Windows 要求开启定位权限才能读取 Wi-Fi 列表\n设置 → 隐私和安全性 → 定位 → 允许桌面应用访问"
        } else if !app.wifi_err.is_empty() {
            &app.wifi_err
        } else {
            "点击「扫描无线信号」开始扫描"
        };
        let cy = wifi_card.y + 60;
        p.text(msg, app.fonts.small, Rect::new(wifi_card.x + 18, cy, wifi_card.w - 36, 44), fade(DIM, a1f), ALIGN_CENTER);
        if perm {
            let b = Rect::new(wifi_card.x + wifi_card.w / 2 - 70, cy + 52, 140, 34);
            button(app, p, ID_SIG_LOCATION, b, "打开定位设置", Kind::Ghost, true, a1f);
        }
    } else if app.wifi.is_empty() && app.wifi_loading {
        p.text("正在扫描…", app.fonts.small, Rect::new(wifi_card.x, wifi_card.y + 70, wifi_card.w, 24), fade(MUTED, a1f), ALIGN_CENTER);
    } else {
        // 表头
        let hy = wifi_card.y + 52;
        let cols = [
            ("SSID", 0, 0.34f32),
            ("信号", 1, 0.16),
            ("BSSID", 2, 0.22),
            ("信道", 3, 0.10),
            ("加密", 4, 0.18),
        ];
        let avail_w = wifi_card.w - 40;
        let mut xs = Vec::new();
        let mut x = wifi_card.x + 20;
        for (name, _, frac) in cols {
            let cw = (avail_w as f32 * frac) as i32;
            xs.push((x, cw));
            p.text(name, app.fonts.tiny, Rect::new(x, hy, cw, 18), fade(MUTED, a1f), ALIGN_NEAR);
            x += cw;
        }
        let row_h = 34;
        let list_top = hy + 24;
        let list_bot = wifi_card.bottom() - 10;
        let visible = ((list_bot - list_top) / row_h).max(0) as usize;
        p.clip(Rect::new(wifi_card.x + 4, list_top - 2, wifi_card.w - 8, list_bot - list_top + 4));
        let (mx, my) = mouse();
        for (i, w) in app.wifi.iter().take(visible).enumerate() {
            let y = list_top + i as i32 * row_h;
            let row = Rect::new(wifi_card.x + 10, y, wifi_card.w - 20, row_h - 3);
            if row.contains(mx, my) {
                p.round_rect(row, 8.0, fade(0xFFFFFF, 0.05 * a1f));
            }
            p.text_vcenter(
                &fit(p, &w.ssid, app.fonts.body_b, xs[0].1 - 60),
                app.fonts.body_b,
                Rect::new(xs[0].0, y, xs[0].1, row_h),
                fade(TEXT, a1f),
                ALIGN_NEAR,
            );
            if w.connected {
                let tag = Rect::new(xs[0].0 + xs[0].1 - 54, y + 9, 48, 17);
                p.round_rect(tag, 8.0, fade(GREEN, 0.16 * a1f));
                p.text_vcenter("已连接", app.fonts.tiny, tag, fade(GREEN, a1f), ALIGN_CENTER);
            }
            let lv = if w.rssi < 0 {
                netradar_core::signals::dbm_level(w.rssi)
            } else {
                netradar_core::signals::quality_level(w.quality)
            };
            bars(p, xs[1].0, y + 9, lv, a1f);
            p.text_vcenter(
                &format!("{}", w.rssi),
                app.fonts.tiny,
                Rect::new(xs[1].0 + 30, y, 40, row_h),
                fade(DIM, a1f),
                ALIGN_NEAR,
            );
            p.text_vcenter(&w.bssid, app.fonts.mono, Rect::new(xs[2].0, y, xs[2].1, row_h), fade(DIM, a1f), ALIGN_NEAR);
            p.text_vcenter(
                &if w.channel > 0 { w.channel.to_string() } else { "-".into() },
                app.fonts.small,
                Rect::new(xs[3].0, y, xs[3].1, row_h),
                fade(DIM, a1f),
                ALIGN_NEAR,
            );
            p.text_vcenter(&w.auth, app.fonts.small, Rect::new(xs[4].0, y, xs[4].1, row_h), fade(PURPLE, a1f), ALIGN_NEAR);
        }
        p.unclip();
    }

    /* 蓝牙 */
    let bt_sub = if app.bt_radios.is_empty() {
        String::new()
    } else {
        app.bt_radios[0].clone()
    };
    let bt_sub = if app.bt_err.is_empty() { bt_sub } else { String::new() };
    section(app, p, bt_card, "蓝牙设备", &bt_sub, a2f);

    if !app.bt_err.is_empty() {
        p.text(
            &app.bt_err,
            app.fonts.small,
            Rect::new(bt_card.x + 18, bt_card.y + 60, bt_card.w - 36, 40),
            fade(DIM, a2f),
            ALIGN_CENTER,
        );
        p.text(
            "提示：需要系统蓝牙适配器；BLE 广播抓取需要专用嗅探硬件",
            app.fonts.tiny,
            Rect::new(bt_card.x + 18, bt_card.y + 96, bt_card.w - 36, 20),
            fade(MUTED, a2f),
            ALIGN_CENTER,
        );
    } else if app.bt.is_empty() {
        p.text(
            if app.bt_loading { "正在扫描附近设备（约 5 秒）…" } else { "未发现设备" },
            app.fonts.small,
            Rect::new(bt_card.x, bt_card.y + 66, bt_card.w, 24),
            fade(MUTED, a2f),
            ALIGN_CENTER,
        );
    } else {
        let hy = bt_card.y + 52;
        let cols = [
            ("设备名", 0.32f32),
            ("地址", 0.24),
            ("类型", 0.14),
            ("信号", 0.12),
            ("状态", 0.18),
        ];
        let avail_w = bt_card.w - 40;
        let mut xs = Vec::new();
        let mut x = bt_card.x + 20;
        for (name, frac) in cols {
            let cw = (avail_w as f32 * frac) as i32;
            xs.push((x, cw));
            p.text(name, app.fonts.tiny, Rect::new(x, hy, cw, 18), fade(MUTED, a2f), ALIGN_NEAR);
            x += cw;
        }
        let row_h = 34;
        let list_top = hy + 24;
        let list_bot = bt_card.bottom() - 30;
        let visible = ((list_bot - list_top) / row_h).max(0) as usize;
        let max_scroll = (app.bt.len() as i32 - visible as i32).max(0);
        app.sig_scroll = app.sig_scroll.clamp(0, max_scroll.max(0));
        let skip = app.sig_scroll as usize;
        if max_scroll > 0 {
            p.text(
                &format!("滚轮查看更多 · 共 {} 个设备", app.bt.len()),
                app.fonts.tiny,
                Rect::new(bt_card.right() - 220, bt_card.y + 17, 200, 18),
                fade(MUTED, a2f),
                ALIGN_FAR,
            );
        }
        p.clip(Rect::new(bt_card.x + 4, list_top - 2, bt_card.w - 8, list_bot - list_top + 4));
        let (mx, my) = mouse();
        for (i, d) in app.bt.iter().skip(skip).take(visible).enumerate() {
            let y = list_top + i as i32 * row_h;
            let row = Rect::new(bt_card.x + 10, y, bt_card.w - 20, row_h - 3);
            if row.contains(mx, my) {
                p.round_rect(row, 8.0, fade(0xFFFFFF, 0.05 * a2f));
            }
            // 圆形设备图标
            let ic = Rect::new(xs[0].0, y + (row_h - 20) / 2, 20, 20);
            p.round_rect(ic, 10.0, fade(BLUE, 0.16 * a2f));
            p.circle(ic.x + 10, ic.y + 10, 2, fade(BLUE, a2f));
            p.text_vcenter(
                &fit(p, &d.name, app.fonts.body_b, xs[0].1 - 30),
                app.fonts.body_b,
                Rect::new(xs[0].0 + 28, y, xs[0].1 - 28, row_h),
                fade(TEXT, a2f),
                ALIGN_NEAR,
            );
            p.text_vcenter(&d.addr, app.fonts.mono, Rect::new(xs[1].0, y, xs[1].1, row_h), fade(DIM, a2f), ALIGN_NEAR);
            p.text_vcenter(&d.kind, app.fonts.small, Rect::new(xs[2].0, y, xs[2].1, row_h), fade(PURPLE, a2f), ALIGN_NEAR);
            match netradar_core::signals::bt_link_hint(d.connected) {
                Some(lv) => {
                    bars(p, xs[3].0, y + 9, lv, a2f);
                    p.text_vcenter(
                        "强",
                        app.fonts.tiny,
                        Rect::new(xs[3].0 + 30, y, 30, row_h),
                        fade(GREEN, a2f),
                        ALIGN_NEAR,
                    );
                }
                None => {
                    p.text_vcenter(
                        "—",
                        app.fonts.tiny,
                        Rect::new(xs[3].0, y, xs[3].1, row_h),
                        fade(MUTED, a2f),
                        ALIGN_NEAR,
                    );
                }
            }
            let (st, sc) = if d.connected {
                ("已连接", GREEN)
            } else if d.remembered {
                ("已配对", BLUE)
            } else {
                ("新发现", AMBER)
            };
            let tag = Rect::new(xs[4].0, y + 8, 58, 18);
            p.round_rect(tag, 9.0, fade(sc, 0.14 * a2f));
            p.text_vcenter(st, app.fonts.tiny, tag, fade(sc, a2f), ALIGN_CENTER);
        }
        p.unclip();
        p.text(
            "经典蓝牙查询不返回 RSSI · 已连接设备按链路状态给出等级",
            app.fonts.tiny,
            Rect::new(bt_card.x + 18, bt_card.bottom() - 21, bt_card.w - 36, 16),
            fade(MUTED, 0.85 * a2f),
            ALIGN_NEAR,
        );
    }
}

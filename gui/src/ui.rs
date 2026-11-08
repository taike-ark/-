//! 界面框架：液态玻璃背景、顶栏胶囊导航、通用控件

use crate::gfx::{Painter, Rect, ALIGN_CENTER, ALIGN_FAR, ALIGN_NEAR, Gp};
use crate::state::*;
use crate::theme::*;

pub const HDR_H: i32 = 62;
pub const FOOT_H: i32 = 34;
pub const PAD: i32 = 22;

pub mod page_about;
pub mod page_capture;
pub mod page_scan;
pub mod page_signals;

/* ---------------------------- 文本工具 ---------------------------- */

pub fn fit(p: &Painter, s: &str, font: Gp, maxw: i32) -> String {
    if p.measure(s, font) <= maxw {
        return s.to_string();
    }
    let mut out: Vec<char> = s.chars().collect();
    while !out.is_empty() {
        out.pop();
        let cand: String = out.iter().collect::<String>() + "…";
        if p.measure(&cand, font) <= maxw {
            return cand;
        }
    }
    String::new()
}

pub fn fade(c: u32, mul: f32) -> u32 {
    let a = ((c >> 24) & 0xFF) as f32 * mul.clamp(0.0, 1.0);
    with_alpha(c, a as u32)
}

/* ---------------------------- 背景 ---------------------------- */

pub fn background(p: &Painter, w: i32, h: i32, _now: u64) {
    // 纯黑背景：层次交给玻璃卡片与高光
    p.rect(Rect::new(0, 0, w, h), 0xFF000000);
}

/* ---------------------------- 玻璃卡片 ---------------------------- */

pub fn glass(p: &Painter, r: Rect, radius: f32, alpha: f32) {
    if r.w <= 2 || r.h <= 2 || alpha <= 0.01 {
        return;
    }
    p.shadow(r, radius, 70);
    let top = fade(0xFFFFFFFF, 0.075 * alpha);
    let bot = fade(0xFFFFFFFF, 0.025 * alpha);
    p.grad(r, top, bot, false, radius);
    p.round_rect_stroke(r, radius, fade(0xFFFFFFFF, 0.10 * alpha), 1.0);
    // 顶部高光
    p.line(
        (r.x as f32 + radius),
        (r.y + 1) as f32,
        (r.right() as f32 - radius),
        (r.y + 1) as f32,
        fade(0xFFFFFFFF, 0.16 * alpha),
        1.0,
    );
}

/* ---------------------------- 控件 ---------------------------- */

pub enum Kind {
    Primary,
    Ghost,
    Danger,
    Chip { on: bool },
}

fn rgba_inner(app: &App, id: u32) -> (f32, bool) {
    (app.hover_alpha(id), app.pressed == id)
}

pub fn button(
    app: &mut App,
    p: &Painter,
    id: u32,
    r: Rect,
    label: &str,
    kind: Kind,
    enabled: bool,
    alpha: f32,
) {
    app.area(id, r);
    let (hv, pressed) = rgba_inner(app, id);
    let hv = if enabled { hv } else { 0.0 };
    let radius = r.h as f32 / 2.0;
    let font = app.fonts.body_b;
    match kind {
        Kind::Primary => {
            let c1 = lerp_color(0xFF22D3EE, 0xFF5CE1F4, hv);
            p.shadow(r, radius, (60.0 * (0.4 + hv * 0.6)) as u32);
            p.grad(r, fade(c1, alpha), fade(0xFF0891B2, alpha), true, radius);
            p.line(
                (r.x as f32 + radius),
                (r.y + 1) as f32,
                (r.right() as f32 - radius),
                (r.y + 1) as f32,
                fade(0xFFFFFFFF, 0.35 * alpha),
                1.0,
            );
            p.text_vcenter(label, font, r, fade(0xFF04121F, alpha), ALIGN_CENTER);
        }
        Kind::Ghost | Kind::Danger => {
            let base = if matches!(kind, Kind::Danger) { RED } else { TEXT };
            let fill = fade(0xFFFFFFFF, (0.06 + hv * 0.07) * alpha);
            p.round_rect(r, radius, fill);
            let border = if matches!(kind, Kind::Danger) {
                fade(RED, (0.35 + hv * 0.35) * alpha)
            } else {
                fade(0xFFFFFFFF, (0.12 + hv * 0.12) * alpha)
            };
            p.round_rect_stroke(r, radius, border, 1.0);
            let tc = if enabled { fade(base, alpha) } else { fade(MUTED, alpha) };
            p.text_vcenter(label, font, r, tc, ALIGN_CENTER);
        }
        Kind::Chip { on } => {
            let fill = if on {
                fade(ACCENT, (0.16 + hv * 0.06) * alpha)
            } else {
                fade(0xFFFFFFFF, (0.05 + hv * 0.06) * alpha)
            };
            p.round_rect(r, radius, fill);
            let border = if on {
                fade(ACCENT, 0.45 * alpha)
            } else {
                fade(0xFFFFFFFF, 0.10 * alpha)
            };
            p.round_rect_stroke(r, radius, border, 1.0);
            let tc = if on { fade(ACCENT, alpha) } else { fade(DIM, alpha) };
            p.text_vcenter(label, app.fonts.small, r, tc, ALIGN_CENTER);
        }
    }
    let _ = pressed;
}

pub fn text_field(
    app: &mut App,
    p: &Painter,
    id: u32,
    r: Rect,
    text: &str,
    placeholder: &str,
    focused: bool,
    alpha: f32,
) {
    app.area(id, r);
    let hv = app.hover_alpha(id);
    let radius = 10.0;
    p.round_rect(r, radius, fade(0xFF0E1319, (0.96 + hv * 0.04) * alpha));
    p.round_rect_stroke(
        r,
        radius,
        if focused {
            fade(ACCENT, 0.65 * alpha)
        } else {
            fade(0xFFFFFF, (0.16 + hv * 0.08) * alpha)
        },
        1.0,
    );
    let inner = Rect::new(r.x + 13, r.y, r.w - 26, r.h);
    if text.is_empty() {
        p.text_vcenter(placeholder, app.fonts.body, inner, fade(MUTED, alpha), ALIGN_NEAR);
    } else {
        p.text_vcenter(text, app.fonts.body, inner, fade(TEXT, alpha), ALIGN_NEAR);
    }
    if focused && ((app.now / 500) % 2 == 0 || (app.now / 500) % 2 == 1) {
        let w = p.measure(text, app.fonts.body);
        let x = inner.x + w + 2;
        if (app.now / 520) % 2 == 0 {
            p.line(
                x as f32,
                (r.y + 10) as f32,
                x as f32,
                (r.bottom() - 10) as f32,
                fade(ACCENT, alpha),
                1.6,
            );
        }
    }
}

pub fn kpi_card(
    app: &mut App,
    p: &Painter,
    r: Rect,
    value: &str,
    label: &str,
    color: u32,
    alpha: f32,
) {
    glass(p, r, 16.0, alpha);
    // 左侧色条
    let bar = Rect::new(r.x + 14, r.y + 16, 3, 26);
    p.round_rect(bar, 1.5, fade(color, 0.85 * alpha));
    p.glow(r.x + 16, r.y + 28, 16, fade(color, 0.14 * alpha));
    p.text(
        value,
        app.fonts.kpi,
        Rect::new(r.x + 26, r.y + 12, r.w - 32, 36),
        fade(color, alpha),
        ALIGN_NEAR,
    );
    p.text(
        label,
        app.fonts.tiny,
        Rect::new(r.x + 26, r.y + 50, r.w - 32, 18),
        fade(DIM, alpha),
        ALIGN_NEAR,
    );
}

/* ---------------------------- 顶栏 ---------------------------- */

fn tab_rect(i: usize, w: i32) -> Rect {
    let tab_w = 92;
    let total = tab_w * 4 + 3 * 6;
    let x0 = (w - total) / 2;
    Rect::new(x0 + i as i32 * (tab_w + 6), (HDR_H - 36) / 2, tab_w, 36)
}

fn draw_header(app: &mut App, p: &Painter, w: i32) {
    p.rect(Rect::new(0, 0, w, HDR_H), fade(0xFF080D16, 0.55));
    p.line(0.0, (HDR_H - 1) as f32, w as f32, (HDR_H - 1) as f32, fade(0xFFFFFF, 0.07), 1.0);

    // Logo
    let cx = 19 + 8;
    let cy = HDR_H / 2;
    p.glow(cx, cy, 22, fade(ACCENT, 0.30));
    p.circle(cx, cy, 8, fade(ACCENT, 0.18));
    p.circle(cx, cy, 3, fade(ACCENT, 1.0));
    p.line(
        cx as f32,
        cy as f32,
        (cx + 9) as f32,
        (cy - 9) as f32,
        fade(ACCENT, 0.55),
        1.4,
    );
    p.text_vcenter(
        "NetRadar",
        app.fonts.logo,
        Rect::new(44, 0, 140, HDR_H),
        fade(TEXT, 1.0),
        ALIGN_NEAR,
    );

    // 导航胶囊（滑动指示器）
    let idx = app.tab_anim.value(app.now);
    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(3);
    let frac = idx - lo as f32;
    let a = tab_rect(lo.min(3), w);
    let b = tab_rect(hi, w);
    let ind = Rect::new(
        (a.x as f32 + (b.x - a.x) as f32 * frac) as i32,
        a.y,
        (a.w as f32 + (b.w - a.w) as f32 * frac) as i32,
        a.h,
    );
    p.glow(ind.x + ind.w / 2, ind.y + ind.h / 2, ind.w / 2 - 4, fade(ACCENT, 0.10));
    p.round_rect(ind, 18.0, fade(ACCENT, 0.16));
    p.round_rect_stroke(ind, 18.0, fade(ACCENT, 0.40), 1.0);

    let labels = ["扫描", "抓包", "信号", "关于"];
    let ids = [ID_TAB_SCAN, ID_TAB_CAPTURE, ID_TAB_SIGNALS, ID_TAB_ABOUT];
    for i in 0..4 {
        let r = tab_rect(i, w);
        app.area(ids[i], r);
        let active = app.page == i;
        let hv = app.hover_alpha(ids[i]);
        let c = if active {
            fade(ACCENT, 1.0)
        } else {
            lerp_color(fade(DIM, 1.0), fade(TEXT, 1.0), hv)
        };
        p.text_vcenter(labels[i], app.fonts.body_b, r, c, ALIGN_CENTER);
    }

    // 状态胶囊
    let (txt, col) = if app.scanning || app.capturing || app.wifi_loading || app.bt_loading {
        ("运行中", AMBER)
    } else {
        ("空闲", GREEN)
    };
    let pill = Rect::new(w - 3 * 42 - 24 - 74, (HDR_H - 26) / 2, 74, 26);
    p.round_rect(pill, 13.0, fade(col, 0.12));
    p.round_rect_stroke(pill, 13.0, fade(col, 0.28), 1.0);
    let pulse = if app.scanning || app.capturing {
        0.5 + 0.5 * ((app.now as f32 / 500.0).sin())
    } else {
        1.0
    };
    p.circle(pill.x + 14, pill.y + 13, 3, fade(col, 0.5 + 0.5 * pulse));
    p.text_vcenter(
        txt,
        app.fonts.tiny,
        Rect::new(pill.x + 24, pill.y, 44, 26),
        fade(col, 1.0),
        ALIGN_NEAR,
    );

    // 窗口按钮
    let bw = 34;
    let bh = 26;
    let y = (HDR_H - bh) / 2;
    for (i, id) in [ID_MIN, ID_MAX, ID_CLOSE].iter().enumerate() {
        let x = w - 12 - (3 - i as i32) * (bw + 4);
        let r = Rect::new(x, y, bw, bh);
        app.area(*id, r);
        let hv = app.hover_alpha(*id);
        let is_close = *id == ID_CLOSE;
        if hv > 0.01 {
            p.round_rect(
                r,
                9.0,
                if is_close {
                    fade(0xFFE5484D, 0.22 * hv)
                } else {
                    fade(0xFFFFFF, 0.10 * hv)
                },
            );
        }
        let c = fade(if is_close && hv > 0.4 { 0xFFFCA5A5 } else { DIM }, 1.0);
        let cx = x + bw / 2;
        let cy = y + bh / 2;
        match *id {
            ID_MIN => p.line((cx - 5) as f32, cy as f32, (cx + 5) as f32, cy as f32, c, 1.5),
            ID_MAX => p.round_rect_stroke(Rect::new(cx - 5, cy - 5, 10, 10), 2.5, c, 1.4),
            _ => {
                p.line((cx - 4) as f32, (cy - 4) as f32, (cx + 4) as f32, (cy + 4) as f32, c, 1.5);
                p.line((cx + 4) as f32, (cy - 4) as f32, (cx - 4) as f32, (cy + 4) as f32, c, 1.5);
            }
        }
    }
}

fn draw_footer(app: &App, p: &Painter, w: i32, h: i32) {
    let y = h - FOOT_H;
    p.line(0.0, y as f32, w as f32, y as f32, fade(0xFFFFFF, 0.06), 1.0);
    p.rect(Rect::new(0, y + 1, w, FOOT_H - 1), fade(0xFF070B12, 0.35));
    let (dot, txt) = match app.status_kind {
        1 => (GREEN, GREEN),
        2 => (AMBER, AMBER),
        3 => (RED, RED),
        _ => (0xFF4D8AC0, DIM),
    };
    p.circle(20, y + 17, 3, fade(dot, 1.0));
    p.text_vcenter(
        &fit(p, &app.status, app.fonts.small, w - 380),
        app.fonts.small,
        Rect::new(32, y, w - 380, FOOT_H),
        fade(txt, 1.0),
        ALIGN_NEAR,
    );
    let right = format!(
        "{} · {}",
        if app.npcap {
            "Npcap"
        } else if app.admin {
            "RAW SOCKET"
        } else {
            "需管理员抓包"
        },
        app.iface
    );
    p.text_vcenter(
        &fit(p, &right, app.fonts.tiny, 300),
        app.fonts.tiny,
        Rect::new(w - 320, y, 300, FOOT_H),
        fade(MUTED, 1.0),
        ALIGN_FAR,
    );
}

/* ---------------------------- 入口 ---------------------------- */

static mut MOUSE: (i32, i32) = (0, 0);

pub fn set_mouse(x: i32, y: i32) {
    unsafe {
        MOUSE = (x, y);
    }
}

pub fn mouse() -> (i32, i32) {
    unsafe { MOUSE }
}

pub fn draw(app: &mut App, p: &Painter, w: i32, h: i32) {
    app.areas.clear();
    draw_ui(app, p, w, h);
}

/// 只画界面层（背景由主程序缓存后 blit）
pub fn draw_ui(app: &mut App, p: &Painter, w: i32, h: i32) {
    draw_header(app, p, w);
    let content = Rect::new(0, HDR_H, w, h - HDR_H - FOOT_H);
    match app.page {
        PAGE_SCAN => page_scan::draw(app, p, content),
        PAGE_CAPTURE => page_capture::draw(app, p, content),
        PAGE_SIGNALS => page_signals::draw(app, p, content),
        _ => page_about::draw(app, p, content),
    }
    draw_footer(app, p, w, h);
}

pub fn content_rect(_w: i32, _h: i32) -> Rect {
    Rect::new(0, HDR_H, 0, 0)
}

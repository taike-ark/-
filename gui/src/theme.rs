//! 液态玻璃主题：半透明层、光球、边框高光

pub const BG_TOP: u32 = 0xFF06090F;
pub const BG_BOT: u32 = 0xFF0A1120;

/// 玻璃卡片
pub const GLASS: u32 = 0x12FFFFFF;
pub const GLASS_HOVER: u32 = 0x1EFFFFFF;
pub const GLASS_STRONG: u32 = 0x1CFFFFFF;

pub const BORDER: u32 = 0x1FFFFFFF;
pub const BORDER_HI: u32 = 0x33FFFFFF;
pub const HILITE: u32 = 0x55FFFFFF;

/// 文字
pub const TEXT: u32 = 0xFFEAF1FB;
pub const DIM: u32 = 0xFF93A4C4;
pub const MUTED: u32 = 0xFF5A6A88;

/// 强调色
pub const ACCENT: u32 = 0xFF22D3EE;
pub const ACCENT_SOFT: u32 = 0x3322D3EE;
pub const GREEN: u32 = 0xFF34D399;
pub const GREEN_SOFT: u32 = 0x2E34D399;
pub const AMBER: u32 = 0xFFF5B942;
pub const AMBER_SOFT: u32 = 0x33F5B942;
pub const RED: u32 = 0xFFF87171;
pub const RED_SOFT: u32 = 0x33F87171;
pub const PURPLE: u32 = 0xFFA78BFA;
pub const BLUE: u32 = 0xFF60A5FA;

/// 背景光球
pub const ORB_CYAN: u32 = 0x5522D3EE;
pub const ORB_VIOLET: u32 = 0x447C3AED;
pub const ORB_TEAL: u32 = 0x3314B8A6;
pub const ORB_ROSE: u32 = 0x33F43F5E;

pub struct Fonts {
    pub family: super::gfx::Gp,
    pub display: super::gfx::Gp,
    pub h1: super::gfx::Gp,
    pub h2: super::gfx::Gp,
    pub h3: super::gfx::Gp,
    pub body: super::gfx::Gp,
    pub body_b: super::gfx::Gp,
    pub small: super::gfx::Gp,
    pub tiny: super::gfx::Gp,
    pub mono: super::gfx::Gp,
    pub kpi: super::gfx::Gp,
    pub logo: super::gfx::Gp,
}

impl Fonts {
    pub fn load() -> Fonts {
        use super::gfx::GdiPlus;
        let family = GdiPlus::font_family("Microsoft YaHei UI");
        let family = if family.is_null() {
            GdiPlus::font_family("Microsoft YaHei")
        } else {
            family
        };
        let mono_family = GdiPlus::font_family("Consolas");
        let mono_family = if mono_family.is_null() { family } else { mono_family };
        Fonts {
            family,
            display: GdiPlus::font(family, 21.0, true),
            h1: GdiPlus::font(family, 18.0, true),
            h2: GdiPlus::font(family, 15.0, true),
            h3: GdiPlus::font(family, 13.5, true),
            body: GdiPlus::font(family, 13.0, false),
            body_b: GdiPlus::font(family, 13.0, true),
            small: GdiPlus::font(family, 11.5, false),
            tiny: GdiPlus::font(family, 10.5, false),
            mono: GdiPlus::font(mono_family, 12.0, false),
            kpi: GdiPlus::font(family, 24.0, true),
            logo: GdiPlus::font(family, 17.0, true),
        }
    }
}

pub fn with_alpha(c: u32, a: u32) -> u32 {
    (c & 0x00FF_FFFF) | (a.min(255) << 24)
}

pub fn lerp_color(a: u32, b: u32, t: f32) -> u32 {
    let t = t.clamp(0.0, 1.0);
    let ca = |s: u32| ((a >> s) & 0xFF) as f32;
    let cb = |s: u32| ((b >> s) & 0xFF) as f32;
    let mut out = 0u32;
    for (i, s) in [24u32, 16, 8, 0].iter().enumerate() {
        let v = (ca(*s) + (cb(*s) - ca(*s)) * t) as u32;
        let _ = i;
        out |= (v & 0xFF) << s;
    }
    out
}

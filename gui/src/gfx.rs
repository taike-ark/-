//! GDI+ 轻量封装：圆角矩形、渐变、文字、测量、双缓冲。

use std::os::raw::{c_void, c_int};
use std::ptr;

pub type Gp = *mut c_void;

#[repr(C)]
struct StartupInput {
    version: u32,
    debug_cb: *mut c_void,
    suppress_bg: i32,
    suppress_ext: i32,
}

#[cfg_attr(target_env = "msvc", link(name = "gdiplus"))]
// gdiplus 通过 build.rs 直接链接 DLL 提供导入
extern "system" {
    fn GdiplusStartup(token: *mut usize, input: *const StartupInput, output: *mut c_void) -> c_int;
    fn GdipCreateFromHDC(hdc: isize, g: *mut Gp) -> c_int;
    fn GdipDeleteGraphics(g: Gp) -> c_int;
    fn GdipSetSmoothingMode(g: Gp, mode: i32) -> c_int;
    fn GdipSetTextRenderingHint(g: Gp, hint: i32) -> c_int;
    fn GdipSetPixelOffsetMode(g: Gp, mode: i32) -> c_int;
    fn GdipCreateSolidFill(color: u32, brush: *mut Gp) -> c_int;
    fn GdipDeleteBrush(b: Gp) -> c_int;
    fn GdipFillRectangleI(g: Gp, b: Gp, x: i32, y: i32, w: i32, h: i32) -> c_int;
    fn GdipCreatePath(fill: i32, p: *mut Gp) -> c_int;
    fn GdipDeletePath(p: Gp) -> c_int;
    fn GdipAddPathArc(p: Gp, x: f32, y: f32, w: f32, h: f32, start: f32, sweep: f32) -> c_int;
    fn GdipAddPathLine(p: Gp, x1: f32, y1: f32, x2: f32, y2: f32) -> c_int;
    fn GdipClosePathFigure(p: Gp) -> c_int;
    fn GdipFillPath(g: Gp, b: Gp, p: Gp) -> c_int;
    fn GdipCreatePen1(color: u32, width: f32, unit: i32, pen: *mut Gp) -> c_int;
    fn GdipDeletePen(p: Gp) -> c_int;
    fn GdipDrawPath(g: Gp, pen: Gp, p: Gp) -> c_int;
    fn GdipCreateLineBrushFromRect(
        rect: *const RectF,
        c1: u32,
        c2: u32,
        mode: i32,
        wrap: i32,
        brush: *mut Gp,
    ) -> c_int;
    fn GdipCreateFontFamilyFromName(name: *const u16, collection: *mut c_void, f: *mut Gp) -> c_int;
    fn GdipDeleteFontFamily(f: Gp) -> c_int;
    fn GdipCreateFont(family: Gp, size: f32, style: i32, unit: i32, font: *mut Gp) -> c_int;
    fn GdipDeleteFont(f: Gp) -> c_int;
    fn GdipCreateStringFormat(flags: i32, lang: u16, fmt: *mut Gp) -> c_int;
    fn GdipDeleteStringFormat(f: Gp) -> c_int;
    fn GdipSetStringFormatAlign(f: Gp, a: i32) -> c_int;
    fn GdipSetStringFormatLineAlign(f: Gp, a: i32) -> c_int;
    fn GdipSetStringFormatTrimming(f: Gp, t: i32) -> c_int;
    fn GdipDrawString(
        g: Gp,
        s: *const u16,
        len: i32,
        font: Gp,
        layout: *const RectF,
        fmt: Gp,
        brush: Gp,
    ) -> c_int;
    fn GdipMeasureString(
        g: Gp,
        s: *const u16,
        len: i32,
        font: Gp,
        layout: *const RectF,
        fmt: Gp,
        bounds: *mut RectF,
        cps: *mut i32,
        lines: *mut i32,
    ) -> c_int;
    fn GdipFillEllipseI(g: Gp, b: Gp, x: i32, y: i32, w: i32, h: i32) -> c_int;
    fn GdipDrawLine(g: Gp, pen: Gp, x1: f32, y1: f32, x2: f32, y2: f32) -> c_int;
    fn GdipCreatePathGradientFromPath(path: Gp, brush: *mut Gp) -> c_int;
    fn GdipSetPathGradientCenterColor(brush: Gp, color: u32) -> c_int;
    fn GdipSetPathGradientSurroundColorsWithCount(
        brush: Gp,
        colors: *const u32,
        count: *mut i32,
    ) -> c_int;
    fn GdipAddPathEllipse(p: Gp, x: f32, y: f32, w: f32, h: f32) -> c_int;
    fn GdipSetClipRectI(g: Gp, x: i32, y: i32, w: i32, h: i32, mode: i32) -> c_int;
    fn GdipResetClip(g: Gp) -> c_int;
    fn GdipScaleWorldTransform(g: Gp, sx: f32, sy: f32, order: i32) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RectF {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && py >= self.y && px < self.x + self.w && py < self.y + self.h
    }
    pub fn inset(&self, d: i32) -> Rect {
        Rect::new(self.x + d, self.y + d, self.w - d * 2, self.h - d * 2)
    }
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
}

pub const ALIGN_NEAR: i32 = 0;
pub const ALIGN_CENTER: i32 = 1;
pub const ALIGN_FAR: i32 = 2;

pub struct GdiPlus {
    token: usize,
}

impl GdiPlus {
    pub fn init() -> GdiPlus {
        let input = StartupInput {
            version: 1,
            debug_cb: ptr::null_mut(),
            suppress_bg: 0,
            suppress_ext: 0,
        };
        let mut token: usize = 0;
        unsafe {
            GdiplusStartup(&mut token, &input, ptr::null_mut());
        }
        GdiPlus { token }
    }

    pub fn font_family(name: &str) -> Gp {
        let mut w: Vec<u16> = name.encode_utf16().collect();
        w.push(0);
        let mut f: Gp = ptr::null_mut();
        unsafe {
            GdipCreateFontFamilyFromName(w.as_ptr(), ptr::null_mut(), &mut f);
        }
        f
    }

    pub fn font(family: Gp, px: f32, bold: bool) -> Gp {
        let mut f: Gp = ptr::null_mut();
        unsafe {
            GdipCreateFont(family, px, if bold { 1 } else { 0 }, 2 /* UnitPixel */, &mut f);
        }
        f
    }

    pub fn format(align: i32) -> Gp {
        let mut f: Gp = ptr::null_mut();
        unsafe {
            // NoWrap(0x1000) | NoClip(0x4000)
            GdipCreateStringFormat(0x1000 | 0x4000, 0, &mut f);
            GdipSetStringFormatAlign(f, align);
            GdipSetStringFormatLineAlign(f, 0);
            GdipSetStringFormatTrimming(f, 1);
        }
        f
    }

    pub fn drop_font(&self, f: Gp) {
        if !f.is_null() {
            unsafe {
                GdipDeleteFont(f);
            }
        }
    }
}

impl Drop for GdiPlus {
    fn drop(&mut self) {
        let _ = self.token;
    }
}

/// 一次绘制会话（绑定到 HDC，通常来自内存位图）
pub struct Painter {
    g: Gp,
}

impl Painter {
    pub fn new(hdc: isize) -> Painter {
        let mut g: Gp = ptr::null_mut();
        unsafe {
            GdipCreateFromHDC(hdc, &mut g);
            GdipSetSmoothingMode(g, 4); // AntiAlias
            GdipSetTextRenderingHint(g, 4); // ClearTypeGridFit
            GdipSetPixelOffsetMode(g, 2);
        }
        Painter { g }
    }

    fn brush(&self, color: u32) -> Gp {
        let mut b: Gp = ptr::null_mut();
        unsafe {
            GdipCreateSolidFill(color, &mut b);
        }
        b
    }

    fn free_brush(&self, b: Gp) {
        unsafe {
            GdipDeleteBrush(b);
        }
    }

    pub fn rect(&self, r: Rect, color: u32) {
        let b = self.brush(color);
        unsafe {
            GdipFillRectangleI(self.g, b, r.x, r.y, r.w, r.h);
        }
        self.free_brush(b);
    }

    pub fn rect_f(&self, x: f32, y: f32, w: f32, h: f32, color: u32) {
        let b = self.brush(color);
        unsafe {
            GdipFillRectangleI(self.g, b, x as i32, y as i32, w as i32, h as i32);
        }
        self.free_brush(b);
    }

    pub fn circle(&self, cx: i32, cy: i32, r: i32, color: u32) {
        let b = self.brush(color);
        unsafe {
            GdipFillEllipseI(self.g, b, cx - r, cy - r, r * 2, r * 2);
        }
        self.free_brush(b);
    }

    fn round_path(&self, r: Rect, radius: f32) -> Gp {
        let mut path: Gp = ptr::null_mut();
        unsafe {
            GdipCreatePath(0, &mut path);
        }
        let d = (radius * 2.0).min(r.w as f32).min(r.h as f32);
        let x = r.x as f32;
        let y = r.y as f32;
        let w = r.w as f32;
        let h = r.h as f32;
        unsafe {
            GdipAddPathArc(path, x, y, d, d, 180.0, 90.0);
            GdipAddPathArc(path, x + w - d, y, d, d, 270.0, 90.0);
            GdipAddPathArc(path, x + w - d, y + h - d, d, d, 0.0, 90.0);
            GdipAddPathArc(path, x, y + h - d, d, d, 90.0, 90.0);
            GdipClosePathFigure(path);
        }
        path
    }

    pub fn round_rect(&self, r: Rect, radius: f32, color: u32) {
        if r.w <= 0 || r.h <= 0 {
            return;
        }
        let path = self.round_path(r, radius);
        let b = self.brush(color);
        unsafe {
            GdipFillPath(self.g, b, path);
            GdipDeletePath(path);
        }
        self.free_brush(b);
    }

    pub fn round_rect_stroke(&self, r: Rect, radius: f32, color: u32, width: f32) {
        if r.w <= 0 || r.h <= 0 {
            return;
        }
        let path = self.round_path(r, radius);
        let mut pen: Gp = ptr::null_mut();
        unsafe {
            GdipCreatePen1(color, width, 2, &mut pen);
            GdipDrawPath(self.g, pen, path);
            GdipDeletePen(pen);
            GdipDeletePath(path);
        }
    }

    /// 竖直/水平线性渐变
    pub fn grad(&self, r: Rect, c1: u32, c2: u32, horizontal: bool, radius: f32) {
        let path = self.round_path(r, radius);
        let rf = RectF {
            x: r.x as f32,
            y: r.y as f32,
            w: r.w as f32,
            h: r.h as f32,
        };
        let mode = if horizontal { 0 } else { 1 };
        let mut b: Gp = ptr::null_mut();
        unsafe {
            GdipCreateLineBrushFromRect(&rf, c1, c2, mode, 0, &mut b);
            GdipFillPath(self.g, b, path);
            GdipDeleteBrush(b);
            GdipDeletePath(path);
        }
    }

    pub fn line(&self, x1: f32, y1: f32, x2: f32, y2: f32, color: u32, width: f32) {
        let mut pen: Gp = ptr::null_mut();
        unsafe {
            GdipCreatePen1(color, width, 2, &mut pen);
            GdipDrawLine(self.g, pen, x1, y1, x2, y2);
            GdipDeletePen(pen);
        }
    }

    /// 径向光晕：由外向内叠加同心圆，得到平滑的发光衰减
    pub fn glow(&self, cx: i32, cy: i32, r: i32, color: u32) {
        if r <= 0 {
            return;
        }
        let base = ((color >> 24) & 0xFF) as u32;
        if base == 0 {
            return;
        }
        let steps = 9;
        let per = (base / 3).clamp(4, 42);
        for i in 0..steps {
            let t = i as f32 / (steps - 1) as f32;
            let rr = (r as f32 * (1.0 - t * 0.92)) as i32;
            if rr <= 0 {
                continue;
            }
            let col = (per << 24) | (color & 0x00FF_FFFF);
            let b = self.brush(col);
            unsafe {
                GdipFillEllipseI(self.g, b, cx - rr, cy - rr, rr * 2, rr * 2);
            }
            self.free_brush(b);
        }
    }

    /// 柔和投影（多层低透明度圆角矩形）
    pub fn shadow(&self, r: Rect, radius: f32, strength: u32) {
        for i in 1..=4u32 {
            let grow = (i * 3) as i32;
            let a = (strength * (5 - i) / 14).min(255);
            let rr = Rect::new(
                r.x - grow,
                r.y - grow + 2,
                r.w + grow * 2,
                r.h + grow * 2,
            );
            self.round_rect(rr, radius + grow as f32, (a << 24) & 0xFF00_0000);
        }
    }

    /// 设置整体缩放（DPI 适配）
    pub fn set_scale(&self, s: f32) {
        if (s - 1.0).abs() > 0.001 {
            unsafe {
                GdipScaleWorldTransform(self.g, s, s, 0);
            }
        }
    }

    pub fn clip(&self, r: Rect) {        unsafe {
            GdipSetClipRectI(self.g, r.x, r.y, r.w.max(0), r.h.max(0), 0);
        }
    }

    pub fn unclip(&self) {
        unsafe {
            GdipResetClip(self.g);
        }
    }

    pub fn text(&self, s: &str, font: Gp, rect: Rect, color: u32, align: i32) {
        if s.is_empty() || font.is_null() {
            return;
        }
        let w: Vec<u16> = s.encode_utf16().collect();
        let layout = RectF {
            x: rect.x as f32,
            y: rect.y as f32,
            w: rect.w as f32,
            h: rect.h as f32,
        };
        let fmt = GdiPlus::format(align);
        let b = self.brush(color);
        unsafe {
            GdipDrawString(self.g, w.as_ptr(), w.len() as i32, font, &layout, fmt, b);
            GdipDeleteStringFormat(fmt);
        }
        self.free_brush(b);
    }

    pub fn text_vcenter(&self, s: &str, font: Gp, rect: Rect, color: u32, align: i32) {
        if font.is_null() {
            return;
        }
        let h = self.text_height(s, font, rect.w);
        let y = rect.y + (rect.h - h) / 2;
        self.text(
            s,
            font,
            Rect::new(rect.x, y, rect.w, h),
            color,
            align,
        );
    }

    pub fn text_height(&self, s: &str, font: Gp, width: i32) -> i32 {
        let w: Vec<u16> = s.encode_utf16().collect();
        let layout = RectF {
            x: 0.0,
            y: 0.0,
            w: width as f32,
            h: 1000.0,
        };
        let mut bounds = RectF::default();
        let fmt = GdiPlus::format(ALIGN_NEAR);
        unsafe {
            GdipMeasureString(
                self.g,
                w.as_ptr(),
                w.len() as i32,
                font,
                &layout,
                fmt,
                &mut bounds,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            GdipDeleteStringFormat(fmt);
        }
        bounds.h.ceil() as i32
    }

    pub fn measure(&self, s: &str, font: Gp) -> i32 {
        if font.is_null() || s.is_empty() {
            return 0;
        }
        let w: Vec<u16> = s.encode_utf16().collect();
        let layout = RectF {
            x: 0.0,
            y: 0.0,
            w: 4000.0,
            h: 200.0,
        };
        let mut bounds = RectF::default();
        let fmt = GdiPlus::format(ALIGN_NEAR);
        unsafe {
            GdipMeasureString(
                self.g,
                w.as_ptr(),
                w.len() as i32,
                font,
                &layout,
                fmt,
                &mut bounds,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            GdipDeleteStringFormat(fmt);
        }
        bounds.w.ceil() as i32
    }
}

impl Drop for Painter {
    fn drop(&mut self) {
        unsafe {
            GdipDeleteGraphics(self.g);
        }
    }
}

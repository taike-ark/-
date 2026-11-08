//! 极简动画引擎：线性/缓出插值，驱动界面过渡与悬停渐变。

#[derive(Clone, Copy, PartialEq)]
pub enum Curve {
    Linear,
    EaseOut,
    EaseInOut,
}

fn ease(curve: Curve, t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    match curve {
        Curve::Linear => t,
        Curve::EaseOut => 1.0 - (1.0 - t) * (1.0 - t) * (1.0 - t),
        Curve::EaseInOut => {
            if t < 0.5 {
                2.0 * t * t
            } else {
                1.0 - (-2.0 * t + 2.0) * (-2.0 * t + 2.0) / 2.0
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct Anim {
    pub from: f32,
    pub to: f32,
    pub start: u64,
    pub dur: u64,
    pub curve: Curve,
}

impl Anim {
    pub fn at(value: f32) -> Anim {
        Anim {
            from: value,
            to: value,
            start: 0,
            dur: 1,
            curve: Curve::EaseOut,
        }
    }

    pub fn animate(&mut self, to: f32, now: u64, dur: u64, curve: Curve) {
        if (self.to - to).abs() < 0.0005 {
            return;
        }
        self.from = self.value(now);
        self.to = to;
        self.start = now;
        self.dur = dur.max(1);
        self.curve = curve;
    }

    pub fn value(&self, now: u64) -> f32 {
        if self.dur == 0 {
            return self.to;
        }
        let elapsed = now.saturating_sub(self.start);
        if elapsed >= self.dur {
            return self.to;
        }
        let t = elapsed as f32 / self.dur as f32;
        self.from + (self.to - self.from) * ease(self.curve, t)
    }

    pub fn active(&self, now: u64) -> bool {
        now.saturating_sub(self.start) < self.dur
    }
}

/// 帧内插值：把 current 平滑推向 target（指数逼近，与帧率无关）
pub fn chase(current: f32, target: f32, dt_ms: f32, half_life: f32) -> f32 {
    if (target - current).abs() < 0.001 {
        return target;
    }
    let k = 0.5f32.powf(dt_ms / half_life.max(1.0));
    current + (target - current) * (1.0 - k)
}

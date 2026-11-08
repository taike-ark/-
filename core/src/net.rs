//! IPv4 网段解析与迭代。

use crate::parse_ip;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub base: u32,
    pub prefix: u8,
}

impl Net {
    pub fn new(base: u32, prefix: u8) -> Net {
        let prefix = prefix.min(32);
        let mask = mask_of(prefix);
        Net {
            base: base & mask,
            prefix,
        }
    }

    pub fn mask(&self) -> u32 {
        mask_of(self.prefix)
    }

    pub fn broadcast(&self) -> u32 {
        self.base | !self.mask()
    }

    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix as u32)
    }

    pub fn contains(&self, ip: u32) -> bool {
        (ip & self.mask()) == self.base
    }

    pub fn is_private(&self) -> bool {
        is_private_v4(self.base)
    }

    /// 解析 "192.168.1.0/24" | "192.168.1.5" | "192.168.1.10-192.168.1.60"
    pub fn parse(s: &str) -> Result<Net, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("空网段".into());
        }
        if let Some((a, p)) = s.rsplit_once('/') {
            // 支持省略 .0 的写法: 192.168.1/24
            let base_ip = if a.matches('.').count() == 2 {
                format!("{}.0", a)
            } else {
                a.to_string()
            };
            let ip = parse_ip(&base_ip).ok_or_else(|| format!("非法地址: {}", a))?;
            let prefix: u8 = p.trim().parse().map_err(|_| format!("非法掩码: {}", p))?;
            if prefix > 32 {
                return Err(format!("掩码越界: /{}", prefix));
            }
            return Ok(Net::new(ip, prefix));
        }
        if let Some((a, b)) = s.split_once('-') {
            let start = parse_ip(a).ok_or_else(|| format!("非法起始地址: {}", a))?;
            let end = if b.contains('.') {
                parse_ip(b).ok_or_else(|| format!("非法结束地址: {}", b))?
            } else {
                let last: u8 = b.trim().parse().map_err(|_| format!("非法结束: {}", b))?;
                (start & 0xFFFF_FF00) | last as u32
            };
            if end < start {
                return Err("结束地址小于起始地址".into());
            }
            let n = end - start + 1;
            if n > (1 << 20) {
                return Err("范围过大（>100 万地址）".into());
            }
            // 用一个足以表达该范围的网段
            let mut prefix = 32u8;
            while prefix > 0 && (1u64 << (32 - prefix as u32)) < n as u64 {
                prefix -= 1;
            }
            return Ok(Net {
                base: start & mask_of(prefix),
                prefix,
            });
        }
        let ip = parse_ip(s).ok_or_else(|| format!("非法地址: {}", s))?;
        Ok(Net::new(ip, 32))
    }

    /// 迭代可探测主机地址（跳过网络号与广播地址）
    pub fn hosts(&self) -> HostIter {
        let size = self.size();
        let (first, last) = if size <= 2 {
            (self.base, self.base.wrapping_add(size as u32 - 1))
        } else {
            (self.base.wrapping_add(1), self.broadcast().wrapping_sub(1))
        };
        HostIter {
            cur: first,
            last,
            done: false,
        }
    }

    pub fn hosts_vec(&self) -> Vec<u32> {
        self.hosts().collect()
    }

    pub fn to_cidr(&self) -> String {
        format!("{}/{}", crate::fmt_ip(self.base), self.prefix)
    }
}

pub struct HostIter {
    cur: u32,
    last: u32,
    done: bool,
}

impl Iterator for HostIter {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.done {
            return None;
        }
        let v = self.cur;
        if v == self.last {
            self.done = true;
        } else {
            self.cur = v.wrapping_add(1);
        }
        Some(v)
    }
}

pub fn mask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        0xFFFF_FFFF
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

pub fn is_private_v4(ip: u32) -> bool {
    let b = ip.to_be_bytes();
    b[0] == 10
        || (b[0] == 172 && (16..=31).contains(&b[1]))
        || (b[0] == 192 && b[1] == 168)
        || (b[0] == 100 && (64..=127).contains(&b[1]))
        || (b[0] == 169 && b[1] == 254)
        || b[0] == 127
}

pub fn prefix_from_mask(mask: u32) -> u8 {
    let mut p = 0u8;
    for i in 0..32 {
        if mask & (0x8000_0000u32 >> i) != 0 {
            p += 1;
        } else {
            break;
        }
    }
    p
}

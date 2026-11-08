//! Android / Linux 实现：getifaddrs + /proc，无需 root。

use super::Iface;
use crate::net::{prefix_from_mask, Net};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

#[repr(C)]
struct Sockaddr {
    family: u16,
    data: [u8; 14],
}

#[repr(C)]
struct IfAddrs {
    next: *mut IfAddrs,
    name: *mut c_char,
    flags: u32,
    addr: *mut Sockaddr,
    netmask: *mut Sockaddr,
    ifu: *mut Sockaddr,
    data: *mut c_void,
}

extern "C" {
    fn getifaddrs(list: *mut *mut IfAddrs) -> c_int;
    fn freeifaddrs(list: *mut IfAddrs);
    fn getnameinfo(
        sa: *const c_void,
        salen: u32,
        host: *mut c_char,
        hostlen: u32,
        serv: *mut c_char,
        servlen: u32,
        flags: c_int,
    ) -> c_int;
    fn getuid() -> u32;
}

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;

fn sockaddr_ip(sa: *const Sockaddr) -> Option<u32> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        let s = &*sa;
        if s.family != 2 {
            return None;
        }
        let b = &s.data[2..6];
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn read_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn iface_mac(name: &str) -> Option<String> {
    let s = read_file(&format!("/sys/class/net/{}/address", name))?;
    crate::oui::normalize_mac(s.trim())
}

fn default_gateway() -> Option<(String, u32)> {
    let txt = read_file("/proc/net/route")?;
    for line in txt.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        if f[1] != "00000000" {
            continue;
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        return Some((f[0].to_string(), gw.swap_bytes()));
    }
    None
}

pub fn interfaces() -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    let gw = default_gateway();
    unsafe {
        let mut list: *mut IfAddrs = ptr::null_mut();
        if getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut cur = list;
        let mut guard = 0;
        while !cur.is_null() && guard < 256 {
            guard += 1;
            let it = &*cur;
            let name = if it.name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(it.name).to_string_lossy().to_string()
            };
            if it.flags & IFF_UP != 0 && it.flags & IFF_LOOPBACK == 0 {
                if let Some(ip) = sockaddr_ip(it.addr) {
                    let mask = sockaddr_ip(it.netmask).unwrap_or(0xFFFF_FF00);
                    let prefix = prefix_from_mask(mask);
                    let is_default = gw.as_ref().map(|(n, _)| *n == name).unwrap_or(false)
                        || (name == "wlan0" && crate::net::is_private_v4(ip));
                    out.push(Iface {
                        index: out.len() as u32,
                        name: name.clone(),
                        ip,
                        prefix,
                        mac: iface_mac(&name),
                        gateway: gw.as_ref().map(|(_, g)| *g),
                        is_default,
                    });
                }
            }
            cur = it.next;
        }
        freeifaddrs(list);
    }
    out.sort_by_key(|i| (!i.is_default, i.index));
    out
}

pub fn default_net() -> Option<(Net, Iface)> {
    let ifs = interfaces();
    if let Some(i) = ifs
        .iter()
        .find(|i| i.is_default && crate::net::is_private_v4(i.ip) && i.prefix < 32)
    {
        return Some((Net::new(i.ip, i.prefix), i.clone()));
    }
    if let Some(i) = ifs
        .iter()
        .find(|i| crate::net::is_private_v4(i.ip) && i.prefix < 32)
    {
        return Some((Net::new(i.ip, i.prefix), i.clone()));
    }
    None
}

pub fn arp_table() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let txt = match read_file("/proc/net/arp") {
        Some(t) => t,
        None => return map,
    };
    for line in txt.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let ip = match crate::parse_ip(f[0]) {
            Some(i) => i,
            None => continue,
        };
        if let Some(mac) = crate::oui::normalize_mac(f[3]) {
            map.insert(ip, mac);
        }
    }
    map
}

/// Android 应用无 CAP_NET_RAW，ICMP 由 TCP 探测替代
pub fn ping(_ip: u32, _timeout_ms: u64) -> Option<u32> {
    None
}

pub fn reverse_dns(ip: u32) -> Option<String> {
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }
    let sa = SockaddrIn {
        family: 2,
        port: 0,
        addr: ip.to_be(),
        zero: [0; 8],
    };
    let mut host = [0i8; 256];
    let rc = unsafe {
        getnameinfo(
            &sa as *const _ as *const c_void,
            16,
            host.as_mut_ptr() as *mut c_char,
            host.len() as u32,
            ptr::null_mut(),
            0,
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let s = unsafe { CStr::from_ptr(host.as_ptr() as *const c_char) }
        .to_string_lossy()
        .trim()
        .to_string();
    if s.is_empty() || s == crate::fmt_ip(ip) {
        None
    } else {
        Some(s)
    }
}

pub fn is_elevated() -> bool {
    unsafe { getuid() == 0 }
}

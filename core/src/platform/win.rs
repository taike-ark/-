//! Windows 原生实现。
//! iphlpapi / advapi32 通过 GetProcAddress 动态绑定（无需导入库），
//! ws2_32 / kernel32 走静态导入。

use super::Iface;
use crate::net::{prefix_from_mask, Net};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::{Once, OnceLock};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const c_char) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(ver: u16, data: *mut c_void) -> i32;
    fn getnameinfo(
        sa: *const c_void,
        salen: i32,
        host: *mut c_char,
        hostlen: u32,
        serv: *mut c_char,
        servlen: u32,
        flags: i32,
    ) -> i32;
    pub fn socket(af: i32, ty: i32, proto: i32) -> usize;
    pub fn bind(s: usize, name: *const c_void, namelen: i32) -> i32;
    pub fn recv(s: usize, buf: *mut c_char, len: i32, flags: i32) -> i32;
    pub fn setsockopt(s: usize, level: i32, optname: i32, optval: *const c_char, optlen: i32) -> i32;
    pub fn WSAIoctl(
        s: usize,
        code: u32,
        inbuf: *mut c_void,
        inlen: u32,
        outbuf: *mut c_void,
        outlen: u32,
        bytes: *mut u32,
        ov: *mut c_void,
        cr: *mut c_void,
    ) -> i32;
    pub fn closesocket(s: usize) -> i32;
    pub fn WSAGetLastError() -> i32;
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/* --------------------------- 动态函数绑定 --------------------------- */

type GetIpAddrTableFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32) -> u32;
type GetIpNetTableFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32) -> u32;
type GetBestInterfaceFn = unsafe extern "system" fn(u32, *mut u32) -> u32;
type GetIfEntryFn = unsafe extern "system" fn(*mut c_void) -> u32;
type GetIpForwardTableFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32) -> u32;
type IcmpCreateFileFn = unsafe extern "system" fn() -> *mut c_void;
type IcmpCloseHandleFn = unsafe extern "system" fn(*mut c_void) -> i32;
type IcmpSendEchoFn = unsafe extern "system" fn(
    *mut c_void,
    u32,
    *mut c_void,
    u16,
    *mut c_void,
    *mut c_void,
    u32,
    u32,
) -> u32;

struct Iphlp {
    get_ip_addr_table: GetIpAddrTableFn,
    get_ip_net_table: GetIpNetTableFn,
    get_best_interface: GetBestInterfaceFn,
    get_if_entry: GetIfEntryFn,
    get_ip_forward_table: GetIpForwardTableFn,
    icmp_create_file: IcmpCreateFileFn,
    icmp_close_handle: IcmpCloseHandleFn,
    icmp_send_echo: IcmpSendEchoFn,
}

unsafe fn sym<T: Copy>(h: *mut c_void, name: &str) -> Option<T> {
    if h.is_null() {
        return None;
    }
    let c = std::ffi::CString::new(name).ok()?;
    let p = GetProcAddress(h, c.as_ptr());
    if p.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy::<*mut c_void, T>(&p))
    }
}

static IPHLP: OnceLock<Option<Iphlp>> = OnceLock::new();

fn iphlp() -> Option<&'static Iphlp> {
    IPHLP
        .get_or_init(|| unsafe {
            let h = LoadLibraryA(b"iphlpapi.dll\0".as_ptr() as *const c_char);
            if h.is_null() {
                return None;
            }
            Some(Iphlp {
                get_ip_addr_table: sym(h, "GetIpAddrTable")?,
                get_ip_net_table: sym(h, "GetIpNetTable")?,
                get_best_interface: sym(h, "GetBestInterface")?,
                get_if_entry: sym(h, "GetIfEntry")?,
                get_ip_forward_table: sym(h, "GetIpForwardTable")?,
                icmp_create_file: sym(h, "IcmpCreateFile")?,
                icmp_close_handle: sym(h, "IcmpCloseHandle")?,
                icmp_send_echo: sym(h, "IcmpSendEcho")?,
            })
        })
        .as_ref()
}

type OpenProcessTokenFn = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
type GetTokenInformationFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
type RegOpenKeyExWFn =
    unsafe extern "system" fn(usize, *const u16, u32, u32, *mut usize) -> i32;
type RegQueryValueExWFn =
    unsafe extern "system" fn(usize, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type RegCloseKeyFn = unsafe extern "system" fn(usize) -> i32;

struct Advapi {
    open_process_token: OpenProcessTokenFn,
    get_token_information: GetTokenInformationFn,
    reg_open_key_ex_w: RegOpenKeyExWFn,
    reg_query_value_ex_w: RegQueryValueExWFn,
    reg_close_key: RegCloseKeyFn,
}

static ADVAPI: OnceLock<Option<Advapi>> = OnceLock::new();

fn advapi() -> Option<&'static Advapi> {
    ADVAPI
        .get_or_init(|| unsafe {
            let h = LoadLibraryA(b"advapi32.dll\0".as_ptr() as *const c_char);
            if h.is_null() {
                return None;
            }
            Some(Advapi {
                open_process_token: sym(h, "OpenProcessToken")?,
                get_token_information: sym(h, "GetTokenInformation")?,
                reg_open_key_ex_w: sym(h, "RegOpenKeyExW")?,
                reg_query_value_ex_w: sym(h, "RegQueryValueExW")?,
                reg_close_key: sym(h, "RegCloseKey")?,
            })
        })
        .as_ref()
}

/* --------------------------- 工具函数 --------------------------- */

fn wsa_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut data = [0u8; 512];
        unsafe {
            WSAStartup(0x0202, data.as_mut_ptr() as *mut c_void);
        }
    });
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_ne_bytes(b)
}

fn read_cstr(buf: &[u8], off: usize, max: usize) -> String {
    let end = (off + max).min(buf.len());
    let slice = &buf[off..end];
    let nul = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).trim().to_string()
}

fn mac_fmt(bytes: &[u8]) -> Option<String> {
    crate::oui::normalize_mac(
        &bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/* --------------------------- 网卡信息 --------------------------- */

#[derive(Clone, Debug)]
struct IpRow {
    ip: u32,
    mask: u32,
    index: u32,
}

fn ip_addr_table() -> Vec<IpRow> {
    let mut out = Vec::new();
    let api = match iphlp() {
        Some(a) => a,
        None => return out,
    };
    unsafe {
        let mut size: u32 = 0;
        let rc = (api.get_ip_addr_table)(ptr::null_mut(), &mut size, 0);
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc = (api.get_ip_addr_table)(buf.as_mut_ptr() as *mut c_void, &mut size, 0);
        if rc != 0 {
            return out;
        }
        let n = read_u32(&buf, 0) as usize;
        for i in 0..n {
            let off = 4 + i * 24;
            if off + 24 > buf.len() {
                break;
            }
            let ip = u32::from_be(read_u32(&buf, off));
            let index = read_u32(&buf, off + 4);
            let mask = u32::from_be(read_u32(&buf, off + 8));
            out.push(IpRow { ip, mask, index });
        }
    }
    out
}

/// GetIfEntry: 返回 (设备名 \DEVICE\TCPIP_{GUID}, MAC)
fn if_entry(index: u32) -> Option<(String, Option<String>)> {
    let api = iphlp()?;
    // MIB_IFROW: wszName[256](512) dwIndex(512) dwType dwMtu dwSpeed dwPhysAddrLen(528)
    //            bPhysAddr[8](532)
    let mut buf = vec![0u8; 1024];
    buf[512..516].copy_from_slice(&index.to_ne_bytes());
    let rc = unsafe { (api.get_if_entry)(buf.as_mut_ptr() as *mut c_void) };
    if rc != 0 {
        return None;
    }
    let mut name = Vec::new();
    for i in 0..255 {
        let off = i * 2;
        let w = u16::from_ne_bytes([buf[off], buf[off + 1]]);
        if w == 0 {
            break;
        }
        name.push(w);
    }
    let name = String::from_utf16_lossy(&name);
    let mac_len = read_u32(&buf, 528) as usize;
    let mac = if mac_len >= 6 {
        mac_fmt(&buf[532..532 + mac_len.min(8)])
    } else {
        None
    };
    Some((name, mac))
}

/// 从注册表取网卡"友好名称"（如 WLAN / 以太网 / VMware Network Adapter VMnet8）
fn adapter_friendly_name(device_name: &str) -> Option<String> {
    let guid = device_name
        .rsplit_once('{')
        .map(|(_, g)| format!("{{{g}"))
        .or_else(|| {
            device_name
                .find('{')
                .map(|i| device_name[i..].to_string())
        })?;
    let path = format!(
        "SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{guid}\\Connection"
    );
    let api = advapi()?;
    const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
    const KEY_READ: u32 = 0x2_0019;
    unsafe {
        let mut key: usize = 0;
        let p = to_wide(&path);
        if (api.reg_open_key_ex_w)(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let mut typ: u32 = 0;
        let mut len: u32 = 1024;
        let mut buf = vec![0u8; 1024];
        let vname = to_wide("Name");
        let rc = (api.reg_query_value_ex_w)(
            key,
            vname.as_ptr(),
            ptr::null_mut(),
            &mut typ,
            buf.as_mut_ptr(),
            &mut len,
        );
        (api.reg_close_key)(key);
        if rc != 0 {
            return None;
        }
        let n = (len as usize / 2).min(buf.len() / 2);
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let w = u16::from_ne_bytes([buf[i * 2], buf[i * 2 + 1]]);
            if w == 0 {
                break;
            }
            v.push(w);
        }
        let s = String::from_utf16_lossy(&v);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

/// 默认网关：路由表中目的地址为 0 的下一跳
fn gateways() -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    let api = match iphlp() {
        Some(a) => a,
        None => return map,
    };
    unsafe {
        let mut size: u32 = 0;
        let rc = (api.get_ip_forward_table)(ptr::null_mut(), &mut size, 0);
        if rc != ERROR_BUFFER_OVERFLOW && rc != ERROR_INSUFFICIENT_BUFFER {
            return map;
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc = (api.get_ip_forward_table)(buf.as_mut_ptr() as *mut c_void, &mut size, 0);
        if rc != 0 {
            return map;
        }
        let n = read_u32(&buf, 0) as usize;
        for i in 0..n {
            let off = 4 + i * 56;
            if off + 56 > buf.len() {
                break;
            }
            let dest = u32::from_be(read_u32(&buf, off));
            let next_hop = u32::from_be(read_u32(&buf, off + 12));
            let if_index = read_u32(&buf, off + 16);
            if dest == 0 && next_hop != 0 {
                map.entry(if_index).or_insert(next_hop);
            }
        }
    }
    map
}

fn best_if_index() -> Option<u32> {
    let api = iphlp()?;
    let mut idx: u32 = 0;
    let dest = u32::from_ne_bytes([8, 8, 8, 8]);
    let rc = unsafe { (api.get_best_interface)(dest, &mut idx) };
    if rc == 0 {
        Some(idx)
    } else {
        None
    }
}

/* --------------------------- 对外接口 --------------------------- */

pub fn interfaces() -> Vec<Iface> {
    wsa_init();
    let rows = ip_addr_table();
    let gws = gateways();
    let best = best_if_index();
    let mut out: Vec<Iface> = Vec::new();
    for r in rows {
        if r.ip == 0 || r.mask == 0 {
            continue;
        }
        let prefix = prefix_from_mask(r.mask);
        let (name, mac) = if r.ip == 0x7F00_0001 {
            ("回环 Loopback".to_string(), None)
        } else {
            match if_entry(r.index) {
            Some((dev, mac)) => {
                let friendly = adapter_friendly_name(&dev).unwrap_or_else(|| {
                    if dev.is_empty() {
                        format!("网卡#{}", r.index)
                    } else {
                        dev.clone()
                    }
                });
                (friendly, mac)
            }
            None => (format!("网卡#{}", r.index), None),
            }
        };
        out.push(Iface {
            index: r.index,
            name,
            ip: r.ip,
            prefix,
            mac,
            gateway: gws.get(&r.index).copied(),
            is_default: best.map(|b| b == r.index).unwrap_or(false),
        });
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
    if let Some(i) = ifs
        .iter()
        .find(|i| i.ip.to_be_bytes()[0] != 127 && i.prefix < 32)
    {
        return Some((Net::new(i.ip, i.prefix), i.clone()));
    }
    None
}

pub fn arp_table() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let api = match iphlp() {
        Some(a) => a,
        None => return map,
    };
    unsafe {
        let mut size: u32 = 0;
        let rc = (api.get_ip_net_table)(ptr::null_mut(), &mut size, 0);
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return map;
        }
        let mut buf = vec![0u8; size as usize + 64];
        let rc = (api.get_ip_net_table)(buf.as_mut_ptr() as *mut c_void, &mut size, 0);
        if rc != 0 {
            return map;
        }
        let n = read_u32(&buf, 0) as usize;
        for i in 0..n {
            let off = 4 + i * 24;
            if off + 24 > buf.len() {
                break;
            }
            let phys_len = read_u32(&buf, off + 4);
            if phys_len != 6 {
                continue;
            }
            let mac = mac_fmt(&buf[off + 8..off + 14]);
            let ip = u32::from_be(read_u32(&buf, off + 16));
            if let Some(mac) = mac {
                map.insert(ip, mac);
            }
        }
    }
    map
}

pub fn ping(ip: u32, timeout_ms: u64) -> Option<u32> {
    let api = iphlp()?;
    unsafe {
        let h = (api.icmp_create_file)();
        if h.is_null() || h as isize == -1 {
            return None;
        }
        let mut payload = [0x4Eu8; 32];
        let mut reply = vec![0u8; 96];
        let dest = ip.to_be();
        let r = (api.icmp_send_echo)(
            h,
            dest,
            payload.as_mut_ptr() as *mut c_void,
            payload.len() as u16,
            ptr::null_mut(),
            reply.as_mut_ptr() as *mut c_void,
            reply.len() as u32,
            timeout_ms.min(5000) as u32,
        );
        (api.icmp_close_handle)(h);
        if r == 0 {
            return None;
        }
        let status = read_u32(&reply, 4);
        let rtt = read_u32(&reply, 8);
        if status == 0 {
            Some(rtt)
        } else {
            None
        }
    }
}

pub fn reverse_dns(ip: u32) -> Option<String> {
    wsa_init();
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
    let api = match advapi() {
        Some(a) => a,
        None => return false,
    };
    unsafe {
        let mut token: *mut c_void = ptr::null_mut();
        if (api.open_process_token)(GetCurrentProcess(), 0x0008, &mut token) == 0 {
            return false;
        }
        let mut info = [0u8; 8];
        let mut ret: u32 = 0;
        let ok = (api.get_token_information)(
            token,
            20,
            info.as_mut_ptr() as *mut c_void,
            4,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && read_u32(&info, 0) == 1
    }
}

//! 无线信号探测：Wi-Fi 热点扫描（wlanapi）与蓝牙适配器/设备扫描（BluetoothAPIs）。
//! 全部通过 GetProcAddress 动态绑定，无需导入库。

use std::os::raw::{c_char, c_void};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, name: *const c_char) -> *mut c_void;
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

fn read_u32(b: &[u8], off: usize) -> u32 {
    let mut x = [0u8; 4];
    x.copy_from_slice(&b[off..off + 4]);
    u32::from_ne_bytes(x)
}

fn read_i32(b: &[u8], off: usize) -> i32 {
    read_u32(b, off) as i32
}

fn read_wstr(b: &[u8], off: usize, max_chars: usize) -> String {
    let mut v = Vec::with_capacity(max_chars);
    for i in 0..max_chars {
        let o = off + i * 2;
        if o + 2 > b.len() {
            break;
        }
        let w = u16::from_ne_bytes([b[o], b[o + 1]]);
        if w == 0 {
            break;
        }
        v.push(w);
    }
    String::from_utf16_lossy(&v)
}

fn mac_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/* ================================ Wi-Fi ================================ */

#[derive(Clone, Debug)]
pub struct WifiAp {
    pub ssid: String,
    pub bssid: String,
    pub rssi: i32,
    pub quality: u32,
    pub auth: String,
    pub cipher: String,
    pub channel: u32,
    pub freq: u32,
    pub connected: bool,
}

fn auth_name(v: u32) -> &'static str {
    match v {
        1 => "开放",
        2 => "WEP共享",
        3 => "WPA",
        4 => "WPA-PSK",
        5 => "WPA-None",
        6 => "WPA2-企业",
        7 => "WPA2-PSK",
        8 => "WPA3",
        9 => "WPA3-SAE",
        10 => "OWE",
        11 => "WPA3-企业",
        _ => "未知",
    }
}

fn cipher_name(v: u32) -> &'static str {
    match v {
        0 => "无",
        1 => "WEP40",
        2 => "TKIP",
        4 => "CCMP",
        5 => "WEP104",
        6 => "BIP",
        8 => "GCMP",
        _ => "未知",
    }
}

fn freq_to_channel(f: u32) -> u32 {
    if (2412..=2472).contains(&f) {
        (f - 2407) / 5
    } else if f == 2484 {
        14
    } else if (5000..=5900).contains(&f) {
        (f - 5000) / 5
    } else if (5955..=7115).contains(&f) {
        (f - 5950) / 5
    } else {
        0
    }
}

type WlanOpenHandleFn = unsafe extern "system" fn(u32, *mut c_void, *mut u32, *mut isize) -> u32;
type WlanCloseHandleFn = unsafe extern "system" fn(isize, *mut c_void) -> u32;
type WlanFreeMemoryFn = unsafe extern "system" fn(*mut c_void);
type WlanEnumInterfacesFn =
    unsafe extern "system" fn(isize, *mut c_void, *mut *mut c_void) -> u32;
type WlanScanFn =
    unsafe extern "system" fn(isize, *const u8, *mut c_void, *mut c_void, *mut c_void) -> u32;
type WlanGetAvailableNetworkListFn =
    unsafe extern "system" fn(isize, *const u8, u32, *mut c_void, *mut *mut c_void) -> u32;
type WlanGetNetworkBssListFn = unsafe extern "system" fn(
    isize,
    *const u8,
    *mut c_void,
    u32,
    i32,
    *mut c_void,
    *mut *mut c_void,
) -> u32;

struct Wlan {
    open: WlanOpenHandleFn,
    close: WlanCloseHandleFn,
    free: WlanFreeMemoryFn,
    enum_ifaces: WlanEnumInterfacesFn,
    scan: WlanScanFn,
    avail: WlanGetAvailableNetworkListFn,
    bss: Option<WlanGetNetworkBssListFn>,
}

fn load_wlan() -> Option<Wlan> {
    unsafe {
        let h = LoadLibraryA(b"wlanapi.dll\0".as_ptr() as *const c_char);
        if h.is_null() {
            return None;
        }
        Some(Wlan {
            open: sym(h, "WlanOpenHandle")?,
            close: sym(h, "WlanCloseHandle")?,
            free: sym(h, "WlanFreeMemory")?,
            enum_ifaces: sym(h, "WlanEnumInterfaces")?,
            scan: sym(h, "WlanScan")?,
            avail: sym(h, "WlanGetAvailableNetworkList")?,
            bss: sym(h, "WlanGetNetworkBssList"),
        })
    }
}

/// 扫描周边 Wi-Fi。`wait_ms` 为触发扫描后等待结果的时间。
pub fn wifi_scan(wait_ms: u64) -> Result<Vec<WifiAp>, String> {
    let w = load_wlan().ok_or_else(|| "NOADAPTER|无法加载 wlanapi.dll（系统缺少无线服务）".to_string())?;
    unsafe {
        let mut negotiated: u32 = 0;
        let mut handle: isize = 0;
        if (w.open)(2, std::ptr::null_mut(), &mut negotiated, &mut handle) != 0 || handle == 0 {
            return Err("OTHER|无法打开 WLAN 服务（WLAN AutoConfig 未运行？）".to_string());
        }
        let mut list: *mut c_void = std::ptr::null_mut();
        let rc = (w.enum_ifaces)(handle, std::ptr::null_mut(), &mut list);
        if rc != 0 || list.is_null() {
            (w.close)(handle, std::ptr::null_mut());
            return Err("NOADAPTER|未找到无线网卡".to_string());
        }
        let n = read_u32(std::slice::from_raw_parts(list as *const u8, 8), 0) as usize;
        if n == 0 {
            (w.free)(list);
            (w.close)(handle, std::ptr::null_mut());
            return Err("NOADAPTER|未找到无线网卡".to_string());
        }
        // 取第一个接口的 GUID
        let base = list as *const u8;
        let mut guid = [0u8; 16];
        std::ptr::copy_nonoverlapping(base.add(8), guid.as_mut_ptr(), 16);
        (w.free)(list);

        // 触发主动扫描
        let _ = (w.scan)(handle, guid.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        if wait_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(wait_ms));
        }

        // 拉取可用网络列表
        let mut avail: *mut c_void = std::ptr::null_mut();
        let rc = (w.avail)(handle, guid.as_ptr(), 0, std::ptr::null_mut(), &mut avail);
        if rc != 0 || avail.is_null() {
            (w.close)(handle, std::ptr::null_mut());
            return Err(if rc == 5 { "PERM|Windows 要求开启定位权限才能读取 Wi-Fi 列表".to_string() } else { format!("OTHER|读取 Wi-Fi 列表失败 rc={}", rc) });
        }
        let hdr = std::slice::from_raw_parts(avail as *const u8, 8);
        let count = read_u32(hdr, 0) as usize;

        // BSS 表：补齐 BSSID / 信道 / RSSI
        let mut bss_map: std::collections::HashMap<String, (String, u32, i32)> =
            std::collections::HashMap::new();
        if let Some(bss_fn) = w.bss {
            let mut blist: *mut c_void = std::ptr::null_mut();
            let rc = bss_fn(
                handle,
                guid.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                &mut blist,
            );
            if rc == 0 && !blist.is_null() {
                let raw = blist as *const u8;
                let hdrs = std::slice::from_raw_parts(raw, 8);
                let n_items = read_u32(hdrs, 4) as usize;
                for i in 0..n_items {
                    let off = 8 + i * 360;
                    let slice = std::slice::from_raw_parts(raw.add(off), 360);
                    let slen = read_u32(slice, 0).min(32) as usize;
                    let ssid = String::from_utf8_lossy(&slice[4..4 + slen]).to_string();
                    let bssid = mac_str(&slice[40..46]);
                    let rssi = read_i32(slice, 56);
                    let freq = read_u32(slice, 92);
                    if rssi < -120 || rssi > 0 {
                        continue;
                    }
                    bss_map.insert(ssid, (bssid, freq, rssi));
                }
                (w.free)(blist);
            }
        }

        let mut out = Vec::new();
        for i in 0..count {
            let off = 8 + i * 628;
            let slice = std::slice::from_raw_parts((avail as *const u8).add(off), 628);
            let slen = read_u32(slice, 512).min(32) as usize;
            let ssid = String::from_utf8_lossy(&slice[516..516 + slen]).to_string();
            if ssid.is_empty() {
                continue;
            }
            let quality = read_u32(slice, 604);
            let secure = read_u32(slice, 608) != 0;
            let auth = read_u32(slice, 612);
            let cipher = read_u32(slice, 616);
            let flags = read_u32(slice, 620);
            let connected = flags & 0x1 != 0;
            let (bssid, freq, rssi) = bss_map
                .get(&ssid)
                .cloned()
                .unwrap_or((String::new(), 0, quality_to_dbm(quality)));
            let quality = if rssi < 0 {
                ((rssi + 100).clamp(0, 60) as u32) * 100 / 60
            } else {
                quality
            };
            out.push(WifiAp {
                ssid,
                bssid,
                rssi,
                quality,
                auth: if secure { auth_name(auth).to_string() } else { "开放".into() },
                cipher: cipher_name(cipher).to_string(),
                channel: freq_to_channel(freq),
                freq,
                connected,
            });
        }
        (w.free)(avail);
        (w.close)(handle, std::ptr::null_mut());
        out.sort_by_key(|a| -(a.rssi));
        Ok(out)
    }
}

/// 打开系统定位隐私设置页（Wi-Fi 扫描受限时引导用户授权）
pub fn open_location_settings() {
    #[cfg_attr(target_env = "msvc", link(name = "shell32"))]
    extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> isize;
    }
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = "ms-settings:privacy-location\0".encode_utf16().collect();
    unsafe {
        ShellExecuteW(0, op.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 1);
    }
}

fn quality_to_dbm(q: u32) -> i32 {
    // 质量 0..100 粗略换算
    -100 + (q.min(100) as i32) * 60 / 100
}

/* ================================ 蓝牙 ================================ */

#[derive(Clone, Debug)]
pub struct BtRadio {
    pub name: String,
    pub addr: String,
    pub class: u32,
}

#[derive(Clone, Debug)]
pub struct BtDevice {
    pub name: String,
    pub addr: String,
    pub class: u32,
    pub connected: bool,
    pub remembered: bool,
    pub authenticated: bool,
}

type BtFindFirstRadioFn = unsafe extern "system" fn(*mut c_void, *mut isize) -> isize;
type BtFindNextRadioFn = unsafe extern "system" fn(isize, *mut isize) -> i32;
type BtFindRadioCloseFn = unsafe extern "system" fn(isize) -> i32;
type BtGetRadioInfoFn = unsafe extern "system" fn(isize, *mut c_void) -> u32;
type BtFindFirstDeviceFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> isize;
type BtFindNextDeviceFn = unsafe extern "system" fn(isize, *mut c_void) -> i32;
type BtFindDeviceCloseFn = unsafe extern "system" fn(isize) -> i32;

struct Bt {
    first_radio: BtFindFirstRadioFn,
    next_radio: BtFindNextRadioFn,
    radio_close: BtFindRadioCloseFn,
    radio_info: BtGetRadioInfoFn,
    first_dev: BtFindFirstDeviceFn,
    next_dev: BtFindNextDeviceFn,
    dev_close: BtFindDeviceCloseFn,
}

fn load_bt() -> Option<Bt> {
    unsafe {
        let h = LoadLibraryA(b"BluetoothAPIs.dll\0".as_ptr() as *const c_char);
        if h.is_null() {
            return None;
        }
        Some(Bt {
            first_radio: sym(h, "BluetoothFindFirstRadio")?,
            next_radio: sym(h, "BluetoothFindNextRadio")?,
            radio_close: sym(h, "BluetoothFindRadioClose")?,
            radio_info: sym(h, "BluetoothGetRadioInfo")?,
            first_dev: sym(h, "BluetoothFindFirstDevice")?,
            next_dev: sym(h, "BluetoothFindNextDevice")?,
            dev_close: sym(h, "BluetoothFindDeviceClose")?,
        })
    }
}

fn bt_addr(bytes: &[u8]) -> String {
    // BLUETOOTH_ADDRESS 低 6 字节，反序显示
    let mut s = Vec::new();
    for i in (0..6).rev() {
        s.push(format!("{:02X}", bytes[i]));
    }
    s.join(":")
}

/// 枚举蓝牙无线电
pub fn bt_radios() -> Vec<BtRadio> {
    let mut out = Vec::new();
    let b = match load_bt() {
        Some(b) => b,
        None => return out,
    };
    unsafe {
        #[repr(C)]
        struct RadioParams {
            dw_size: u32,
        }
        let params = RadioParams { dw_size: 4 };
        let mut radio: isize = 0;
        let find = (b.first_radio)(&params as *const _ as *mut c_void, &mut radio);
        if find == 0 || find == -1 {
            return out;
        }
        loop {
            if radio != 0 {
                // BLUETOOTH_RADIO_INFO: dwSize, addr[8], szName[248], class, lmp, manuf
                let mut buf = vec![0u8; 520];
                buf[0..4].copy_from_slice(&520u32.to_ne_bytes());
                if (b.radio_info)(radio, buf.as_mut_ptr() as *mut c_void) == 0 {
                    let name = read_wstr(&buf, 16, 248);
                    let addr = bt_addr(&buf[8..14]);
                    let class = read_u32(&buf, 512);
                    out.push(BtRadio { name, addr, class });
                }
            }
            let mut next: isize = 0;
            if (b.next_radio)(find, &mut next) == 0 {
                break;
            }
            radio = next;
        }
        (b.radio_close)(find);
    }
    out
}

/// 扫描附近蓝牙设备。inquiry=true 时发起真实查询（较慢，约 5 秒）。
pub fn bt_scan(inquiry: bool, timeout_units: u8) -> Result<(Vec<BtRadio>, Vec<BtDevice>), String> {
    let b = load_bt().ok_or_else(|| "无法加载 BluetoothAPIs.dll".to_string())?;
    let radios = bt_radios();
    if radios.is_empty() {
        return Err("未检测到蓝牙适配器".to_string());
    }
    let mut devices = Vec::new();
    unsafe {
        #[repr(C)]
        struct SearchParams {
            dw_size: u32,
            f_return_authenticated: i32,
            f_return_remembered: i32,
            f_return_unknown: i32,
            f_return_connected: i32,
            f_issue_inquiry: i32,
            c_timeout_multiplier: u8,
            _pad: [u8; 7],
            h_radio: isize,
        }
        let params = SearchParams {
            dw_size: std::mem::size_of::<SearchParams>() as u32,
            f_return_authenticated: 1,
            f_return_remembered: 1,
            f_return_unknown: if inquiry { 1 } else { 0 },
            f_return_connected: 1,
            f_issue_inquiry: if inquiry { 1 } else { 0 },
            c_timeout_multiplier: timeout_units.max(1),
            _pad: [0; 7],
            h_radio: 0,
        };
        // BLUETOOTH_DEVICE_INFO: 空结构 + dwSize
        let mut info = vec![0u8; 560];
        info[0..4].copy_from_slice(&560u32.to_ne_bytes());
        let find = (b.first_dev)(
            &params as *const _ as *mut c_void,
            info.as_mut_ptr() as *mut c_void,
        );
        if find == 0 || find == -1 {
            return Ok((radios, devices));
        }
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 256 {
                break;
            }
            let name = read_wstr(&info, 64, 248);
            let addr = bt_addr(&info[8..14]);
            let class = read_u32(&info, 16);
            let connected = read_u32(&info, 20) != 0;
            let remembered = read_u32(&info, 24) != 0;
            let auth = read_u32(&info, 28) != 0;
            devices.push(BtDevice {
                name: if name.is_empty() { "（未知设备）".into() } else { name },
                addr,
                class,
                connected,
                remembered,
                authenticated: auth,
            });
            let mut ok = (b.next_dev)(find, info.as_mut_ptr() as *mut c_void);
            if ok == 0 {
                break;
            }
            ok = 0;
            let _ = ok;
        }
        (b.dev_close)(find);
    }
    devices.sort_by(|a, b2| b2.connected.cmp(&a.connected));
    Ok((radios, devices))
}

/// 通用蓝牙设备类别解码
pub fn bt_class_name(class: u32) -> &'static str {
    let major = (class >> 8) & 0x1F;
    match major {
        1 => "电脑",
        2 => "手机",
        3 => "网络设备",
        4 => "音频/视频",
        5 => "外设",
        6 => "成像设备",
        7 => "可穿戴",
        8 => "玩具",
        9 => "健康设备",
        _ => "其他",
    }
}

/* ============================ 信号强度换算 ============================ */

/// dBm → 0..4 信号格（与手机状态栏同一套阈值）
pub fn dbm_level(dbm: i32) -> u8 {
    if dbm >= -55 {
        4
    } else if dbm >= -67 {
        3
    } else if dbm >= -78 {
        2
    } else if dbm >= -89 {
        1
    } else {
        0
    }
}

/// 0..100 质量 → 0..4 信号格
pub fn quality_level(q: u32) -> u8 {
    (q.min(100) / 25) as u8
}

/// 蓝牙链路提示。Windows 经典蓝牙查询不返回 RSSI，
/// 只有"已连接"可以确定链路可用，其余返回 None（界面显示为 —）
pub fn bt_link_hint(connected: bool) -> Option<u8> {
    if connected {
        Some(4)
    } else {
        None
    }
}
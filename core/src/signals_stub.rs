//! 非 Windows 平台的信号扫描占位实现（Android 端由 Java 的 BLE/Wi-Fi 扫描承担）。

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

pub fn wifi_scan(_wait_ms: u64) -> Result<Vec<WifiAp>, String> {
    Err("当前平台不支持原生 Wi-Fi 扫描".into())
}

pub fn bt_radios() -> Vec<BtRadio> {
    Vec::new()
}

pub fn bt_scan(_inquiry: bool, _timeout_units: u8) -> Result<(Vec<BtRadio>, Vec<BtDevice>), String> {
    Err("当前平台不支持原生蓝牙扫描".into())
}

pub fn bt_class_name(_class: u32) -> &'static str {
    "其他"
}
pub fn dbm_level(dbm: i32) -> u8 {
    if dbm >= -55 { 4 } else if dbm >= -67 { 3 } else if dbm >= -78 { 2 } else if dbm >= -89 { 1 } else { 0 }
}

pub fn quality_level(q: u32) -> u8 {
    (q.min(100) / 25) as u8
}

pub fn bt_link_hint(connected: bool) -> Option<u8> {
    if connected { Some(4) } else { None }
}
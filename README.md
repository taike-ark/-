<div align="center">

# NetRadar

**网络发现 · 端口指纹 · 流量抓包 · 无线信号探测**

Rust 引擎 + 原生自绘界面 —— Windows 桌面 / 命令行 / Android 三端同源

[![License](https://img.shields.io/badge/license-MIT-22d3ee.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Java](https://img.shields.io/badge/Android-API%2024%2B-3ddc84.svg)](https://developer.android.com)
[![Dependencies](https://img.shields.io/badge/crates-0-success.svg)](#零依赖)

</div>

---

## 它是什么

NetRadar 是一个**离线、零依赖、三端同源**的网络安全工具集：

* **主机发现**：ARP + ICMP + TCP 三重探测，自动降级
* **端口扫描**：TCP connect + banner 指纹（70 个常见端口）
* **流量抓包**：Npcap / 系统 RAW SOCKET，自研 BPF 子集过滤，pcap 落盘
* **无线信号**：Wi-Fi 热点（dBm + 信号格）、蓝牙设备发现
* **报告导出**：JSON / CSV / HTML

三个产物共用同一份 Rust 内核：Windows 桌面 GUI、Windows 命令行、Android APK。

## English

NetRadar is a zero-dependency network toolkit written in Rust with native front-ends:
a **Win32 + GDI+ desktop app** (custom glass UI, no Electron/Qt/.NET), a CLI, and an
**Android app** that ships the very same Rust engine as an executable ELF inside the APK
and drives it over a JSONL event stream (so there is no JNI glue at all).

It performs ARP/ICMP/TCP host discovery, TCP port scanning with banner grabbing,
live packet capture (Npcap or raw sockets) with a hand-written filter parser,
and Wi-Fi / Bluetooth signal scanning.

License: MIT. Use it only on networks you own or are authorised to test.

---

## 截图

**Windows 桌面**（1240×820，125% DPI）

| 扫描 | 抓包 |
|---|---|
| ![scan](docs/screenshots/01-scan.png) | ![capture](docs/screenshots/02-capture.png) |

| 无线信号 | 关于 |
|---|---|
| ![signals](docs/screenshots/03-signals.png) | ![about](docs/screenshots/04-about.png) |

**Android**（vivo V1921A · Android 10 实机）

| 扫描 | 信号 | 抓包 |
|---|---|---|
| ![a-scan](docs/screenshots/android-01-scan.png) | ![a-signals](docs/screenshots/android-02-signals.png) | ![a-capture](docs/screenshots/android-03-capture.png) |

---

## 功能对比

| 能力 | Windows GUI | CLI | Android |
|---|---|---|---|
| 存活主机发现（ARP / ICMP / TCP） | ✅ | ✅ | ✅ |
| MAC 地址 + 厂商识别（200+ OUI 前缀） | ✅ | ✅ | ⚠️ 系统限制见 FAQ |
| 反向主机名解析 | ✅ | ✅ | ✅ |
| 端口扫描 + banner 指纹 | ✅ | ✅ | ✅ |
| 抓包 + BPF 风格过滤 + pcap | ✅ | ✅ | ✅ |
| Wi-Fi 热点扫描（dBm + 信号格） | ✅ | ✅ | ✅ |
| 蓝牙设备发现 | ✅（无 RSSI，见 FAQ） | ✅ | ✅（含 RSSI） |
| 报告导出 | HTML/CSV/JSON | HTML/CSV/JSON | CSV |

---

## 快速开始

### Windows 桌面版

从 Releases 页面下载 `NetRadar-1.0.0-win64.exe`，双击即可 —— 单文件，无需安装、无需运行库。
（发布时把构建好的 exe / apk 作为 Release 附件上传即可。）

### Windows 命令行版

```powershell
netradar-cli-1.0.0-win64.exe -r 192.168.1.0/24 -p top100 --html report.html
netradar-cli-1.0.0-win64.exe -s 192.168.1.10 -p 1-1024
netradar-cli-1.0.0-win64.exe -c -f "tcp port 443" -n 50 -w https.pcap
netradar-cli-1.0.0-win64.exe --signals
netradar-cli-1.0.0-win64.exe --ping 192.168.1.10   # 诊断为什么扫不到
```

抓包需要**管理员权限**（或安装 Npcap）。

### Android

```bash
adb install -r NetRadar-1.0.0-arm64.apk
adb shell am start -n com.netradar.app/.MainActivity
```

> 部分国产 ROM（vivo/OPPO 等）从文件管理器安装时会弹「外部来源应用」风险确认，
> 勾选「已了解风险」再点「继续安装」；或者直接用上面的 `adb install`。

---

## 从源码构建

### 前置

| 依赖 | 版本 | 说明 |
|---|---|---|
| Rust | 1.75+ | `cargo` 即可，项目**零第三方 crate**，无需联网拉依赖 |
| Android SDK | platform 29 + build-tools 29.x | 打包 APK 用 |
| Android NDK | r25c | 交叉编译 arm64 引擎 |
| JDK | **17**（推荐） | 打包 APK 用；JDK 21+ 跑 build-tools 29 的 d8 会失败 |

### Windows

```powershell
# 官方 MSVC 工具链（Windows SDK 自带 gdi32/gdiplus/shell32 导入库）
cargo build --release -p netradar-gui
cargo build --release -p netradar

# 或者 GNU/gnullvm 工具链（build.rs 会用 DLL 直接生成导入，不需要 MinGW）
rustup target add x86_64-pc-windows-gnullvm
cargo build --release --target x86_64-pc-windows-gnullvm -p netradar-gui
```

产物：`target/<triple>/release/NetRadar.exe`（GUI）与 `netradar-cli.exe`（CLI）。

### Android

```powershell
# 1) 交叉编译引擎（用环境变量告诉 cargo 你的 NDK 在哪）
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = "-C link-arg=--target=aarch64-linux-android24 -C link-arg=--sysroot=$ndk/toolchains/llvm/prebuilt/windows-x86_64/sysroot"
cargo build --release -p netradar --target aarch64-linux-android

# 2) 打包 APK（aapt2 → javac → d8 → zipalign → apksigner，不依赖 Gradle）
powershell -ExecutionPolicy Bypass -File build\build_apk.ps1
```

### 一键脚本

```powershell
powershell -ExecutionPolicy Bypass -File build\build_all.ps1
# 可选参数：-Target x86_64-pc-windows-msvc / -Ndk "C:\android-ndk-r25c"
```

脚本会把 GUI、CLI、APK 一起产出到 `dist/`。

> 首次打包 APK 会自动生成 `build/netradar.keystore`（口令 `netradar2026`，仅用于调试）。
> **正式发布请换成你自己的签名密钥。**

---

## 项目结构

```
netradar/
├─ core/                    # Rust 引擎（零依赖，~3.9k 行）
│  └─ src/
│     ├─ net.rs             # CIDR 解析 / 网段迭代
│     ├─ scan.rs            # 三重探测、端口扫描、banner
│     ├─ capture.rs         # 报文解析、过滤器、pcap、Npcap/RAW 后端
│     ├─ signals.rs         # Wi-Fi(wlanapi) / 蓝牙(BluetoothAPIs) 扫描
│     ├─ platform/          # Windows(iphlpapi/注册表) 与 Android(getifaddrs/proc)
│     ├─ oui.rs             # MAC 厂商库（200+ 前缀，二分查找）
│     ├─ services.rs        # 端口→服务名、top100 端口集
│     └─ report.rs          # JSON / CSV / HTML
├─ gui/                     # Windows 桌面 GUI（Win32 + GDI+ 全自绘，~3.4k 行）
│  └─ src/
│     ├─ main.rs            # 窗口、消息循环、DPI、输入
│     ├─ gfx.rs             # GDI+ 封装（圆角/渐变/光晕/阴影/缩放）
│     ├─ anim.rs            # 线性与缓出插值、指数逼近
│     ├─ ui.rs              # 顶栏胶囊导航 + 通用控件
│     └─ ui/page_*.rs       # 扫描 / 抓包 / 信号 / 关于 四个页面
├─ cli/                     # 控制台前端 + REPL（~1.3k 行）
├─ android/                 # Java 应用（~1.6k 行）+ 打包脚本
│  └─ src/com/netradar/app/
│     ├─ MainActivity.java  # 三页 UI（扫描/抓包/信号）
│     ├─ NativeRunner.java  # 启动并驱动 Rust 引擎（JSONL）
│     ├─ CaptureService.java# VpnService 抓包
│     ├─ SignalBars.java    # 信号强度格
│     └─ RadarView.java     # 空状态雷达动画
├─ build/                   # build_all.ps1 / build_apk.ps1
└─ docs/screenshots/
```

---

## 实现原理

### 1. 主机发现：三重判定 + ARP 回读

```
目标 IP ─▶ ARP 缓存命中? ──▶ 在线（链路层已确认，最可靠）
             │否
             ├─▶ ICMP Echo ──▶ 在线
             │       │未响应
             │       └─▶ TCP connect ──▶ 开放 / RST 也算在线
             └─▶ 扫描后再读一次 ARP 表，把"ARP 通了但屏蔽 ICMP/TCP"的主机补回来
```

最后一步很关键：校园网、企业防火墙常把 ICMP 和探测端口全掐了，但**链路层握手藏不住**。
Windows 侧走 `GetIpNetTable`，Android 侧在 Android 10+ 读不到 `/proc/net/arp`（系统限制），所以手机端主要靠 TCP。

### 2. 抓包：双后端 + 自研过滤器

* Npcap 存在 → `LoadLibrary("wpcap.dll")` 动态绑定，抓以太网帧（pcap linktype 1）
* 否则 → `SOCK_RAW + SIO_RCVALL` 混杂接收 IP 层（linktype 101）

过滤器是自己写的递归下降解析器，支持 `and/or/not/括号` 与 BPF 风格的隐式 AND：

```
tcp port 443
udp or icmp
not tcp and host 10.0.0.5
```

### 3. 无线信号

* Wi-Fi：`wlanapi.dll`（`WlanOpenHandle` → `WlanScan` → `WlanGetAvailableNetworkList` + `WlanGetNetworkBssList` 取 BSSID/信道/RSSI）
* 蓝牙：`BluetoothAPIs.dll`（`BluetoothFindFirstRadio` 枚举无线电 + `BluetoothFindFirstDevice` 以查询模式发现附近设备）
* 信号格统一换算：`≥-55` 4 格 / `≥-67` 3 格 / `≥-78` 2 格 / `≥-89` 1 格

### 4. 桌面界面：Win32 + GDI+ 手绘

无 Electron / Qt / .NET。窗口无边框，自实现 `WM_NCHITTEST` 缩放与标题栏拖拽；
玻璃卡片 = 半透明渐变 + 1px 高光描边 + 顶部镜面高光 + 多层低透明度投影；
动画由 16ms 定时器驱动（页面错峰滑入、导航指示器滑动、悬停渐变、数字滚动）。

**DPI**：按 `GetDpiForWindow` 设置 GDI+ 世界变换，布局在逻辑坐标下进行，125%/150% 不跑位。

### 5. Android 桥接：不写 JNI

把 Rust 编成可执行 ELF，塞进 `lib/arm64-v8a/libnetradar.so`；Java 用 `ProcessBuilder` 启动，
stdout 读 JSONL 事件流（`{"ev":"host",...}`），抓包时把 VpnService 的 tun 报文按
「4 字节长度 + 报文」喂给引擎 stdin。省掉了手写 JNI 函数表的风险，也保证两端跑的是同一份扫描代码。

---

## CLI 参考

| 选项 | 说明 |
|---|---|
| `-r, --range <网段>` | `192.168.1.0/24`、`10.0.0.1-10.0.0.99`、`192.168.1/24` |
| `-p, --ports <列表>` | `22,80,443`、`1-1024`、`top100`、`all` |
| `-s, --scan <IP>` | 单机端口扫描 + 指纹 |
| `--timeout / --threads` | 超时（默认 400ms）/ 并发（默认 128） |
| `-c, --capture` | 抓包（需管理员或 Npcap） |
| `-f, --filter <表达式>` | `tcp`、`udp`、`icmp`、`arp`、`host 1.2.3.4`、`port 80`、`tcp port 443`、`not tcp` |
| `-n, --count` / `-d, --duration` | 抓包数量 / 时长 |
| `-w, --write <文件>` | 保存 pcap |
| `--json/--csv/--html` | 导出报告 |
| `--signals` | Wi-Fi + 蓝牙扫描 |
| `--ping <IP>` | 诊断单个地址的可达性 |
| 无参数 | 进入交互式 REPL |

---

## FAQ / 已知限制

**Q：Windows 扫不到 Wi-Fi？**
Windows 10 1903+ 起，读取 Wi-Fi 列表需要**定位权限**（`netsh wlan show networks` 同样被拦）。
打开 设置 → 隐私和安全性 → 定位 → 允许桌面应用访问位置，然后重扫。

**Q：桌面端蓝牙为什么没有信号强度？**
经典蓝牙查询（`BluetoothFindFirstDevice`）返回的 `BLUETOOTH_DEVICE_INFO` **没有 RSSI 字段**，
Windows 也没有等价 Win32 API。桌面端只有"已连接"设备会给出链路等级，其余显示 `—`；
**Android 端能拿到真实 RSSI**（`BluetoothDevice.EXTRA_RSSI`）。

**Q：Android 上为什么 MAC 显示"未知"？**
Android 10 起普通应用不能读 `/proc/net/arp`，拿不到对端 MAC，界面如实标注而不是显示 `-`。

**Q：为什么是 TCP connect 而不是 SYN 扫描？**
SYN 半开需要原始套接字/驱动权限。当前实现无特权即可用（抓包除外）。

**其他限制**：不支持 IPv6 / UDP 端口扫描 / OS 指纹；BLE 广播级嗅探需要专用硬件。

---

## Roadmap

- [ ] BLE 广播监听（WinRT `BluetoothLEAdvertisementWatcher`，带真实 RSSI）
- [ ] SYN 半开扫描（依赖 Npcap）
- [ ] IPv6 支持
- [ ] 扫描结果历史对比 / 资产变更告警
- [ ] macOS / Linux 桌面端（core 已经有 `getifaddrs` 路径）

---

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。欢迎 issue / PR，尤其是：

* 新的 OUI 厂商前缀（`core/src/oui.rs`，注意保持按前缀升序）
* 端口指纹库扩充（`core/src/services.rs`）
* 更多平台的 `platform/` 实现

---

## 许可证

[MIT](LICENSE) © 2026 NetRadar contributors

## 免责声明

本工具仅用于**自有网络或已获授权网络**的资产盘点、连通性排查与故障定位。
未经授权对他人网络进行扫描、抓包或无线信号采集，可能违反当地法律法规与网络使用协议，
请自行承担使用责任。作者不对任何滥用行为负责。

# 贡献指南

感谢你愿意参与 NetRadar！

## 开发环境

| 依赖 | 版本 | 备注 |
|---|---|---|
| Rust | 1.75+ | `cargo build` 即可，项目零第三方 crate |
| JDK | 17 | 打包 APK 用（JDK 21+ 跑 build-tools 29 的 d8 会失败） |
| Android SDK | platform 29 / build-tools 29.x | `aapt2`、`zipalign`、`apksigner`、`d8.jar` |
| Android NDK | r25c | 交叉编译 arm64 引擎 |

## 常用命令

```powershell
# 桌面 GUI（调试运行）
cargo run -p netradar-gui

# 命令行
cargo run -p netradar -- -r 192.168.1.0/24 -p top100

# 只做类型检查（最快）
cargo check -p netradar-core
```

界面调试有几个环境变量开关（不想要可以忽略）：

| 变量 | 作用 |
|---|---|
| `NETRADAR_PAGE=scan\|capture\|signals\|about` | 启动直接进某个页面 |
| `NETRADAR_AUTOSCAN=1` | 启动后自动扫描本机网段 |
| `NETRADAR_SIGNALS=1` | 启动后自动扫 Wi-Fi/蓝牙 |
| `NETRADAR_DEMO=1` | 往抓包页塞几条示例报文（用于截图） |

## 代码约定

* **零依赖**：不引入第三方 crate。需要系统能力时手写 FFI（`platform/` 已有大量例子）。
* **Rust**：`cargo fmt` + `cargo clippy` 保持干净；`unsafe` 块要写清为什么安全。
* **中文注释**：项目以中文注释为主，变量/函数名用英文。
* **UI**：改界面请附截图（Windows 用 `PrintWindow` 截图，Android 用 `adb exec-out screencap`）。
* **功率**：Windows 的 `iphlpapi` / `BluetoothAPIs` / `wlanapi` 都用 `GetProcAddress` 动态绑定，
  新增系统调用请沿用这个模式，避免破坏"单个 exe、无导入库依赖"的特性。

## 提交 PR

1. Fork 并新建分支：`feat/xxx` 或 `fix/xxx`
2. 提交前自测：
   ```powershell
   cargo check -p netradar-core
   cargo build --release -p netradar-gui
   powershell -ExecutionPolicy Bypass -File build\build_all.ps1
   ```
3. PR 描述里写清楚：**改了什么、为什么、怎么验证的**（附截图更好）

## 特别欢迎的贡献

* **OUI 厂商前缀**：`core/src/oui.rs`，数组必须按前缀字符串升序（二分查找依赖顺序）
* **端口指纹**：`core/src/services.rs`
* **新平台**：`core/src/platform/` 下按 `cfg(target_os)` 增加实现（macOS 的 `getifaddrs` 已可直接复用）
* **翻译**：README / UI 文案的英文版本

## 报告问题

请附上：

* 系统版本（`winver`）、权限（是否管理员）、是否安装 Npcap
* 复现步骤与期望结果
* CLI 的话给完整命令行 + 输出；GUI 的话给截图

## 行为准则

请保持友善、就事论事。任何针对未授权网络的攻击性使用都与本项目无关，也不被鼓励。

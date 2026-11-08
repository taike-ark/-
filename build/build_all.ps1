# NetRadar - one-shot build: Windows GUI + CLI + Android APK (ASCII only)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File build\build_all.ps1
#   powershell ... -File build\build_all.ps1 -Ndk "C:\android-ndk-r25c" -Target x86_64-pc-windows-msvc
#
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$Target = "x86_64-pc-windows-gnullvm",
    [string]$Ndk = "",
    [string]$RustBin = ""
)

$ErrorActionPreference = "Continue"

$dist = Join-Path $Root "dist"
$rel = Join-Path $Root "target\$Target\release"

if ($RustBin -ne "") {
    $env:Path = "$RustBin;" + $env:Path
}
if (Test-Path (Join-Path $Root "_toolchain\rust\bin")) {
    $env:Path = (Join-Path $Root "_toolchain\rust\bin") + ";" + $env:Path
    $env:CARGO_HOME = Join-Path $Root "_toolchain\cargo-home"
}

# Android 交叉编译配置（避免把每个人的 NDK 路径写进 .cargo/config.toml）
if ($Ndk -eq "") {
    $cand = Join-Path $Root "_toolchain\ndk\android-ndk-r25c"
    if (Test-Path $cand) { $Ndk = $cand }
}
if ($Ndk -ne "" -and (Test-Path $Ndk)) {
    $prebuilt = Join-Path $Ndk "toolchains\llvm\prebuilt\windows-x86_64"
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = Join-Path $prebuilt "bin\clang.exe"
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = "-C link-arg=--target=aarch64-linux-android24 -C link-arg=--sysroot=$prebuilt/sysroot"
}

New-Item -ItemType Directory -Force $dist | Out-Null

Write-Host "`n==> [1/3] build Windows: GUI + CLI ($Target)" -ForegroundColor Cyan
Push-Location $Root
cargo build --release -p netradar-gui --target $Target
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "gui build failed" }
cargo build --release -p netradar --target $Target
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cli build failed" }
Pop-Location

$gui = Join-Path $rel "NetRadar.exe"
$cli = Join-Path $rel "netradar-cli.exe"
if (-not (Test-Path $gui)) { throw "GUI binary not produced" }
if (-not (Test-Path $cli)) { throw "CLI binary not produced" }

Copy-Item $gui (Join-Path $dist "NetRadar-1.0.0-win64.exe") -Force
Copy-Item $cli (Join-Path $dist "netradar-cli-1.0.0-win64.exe") -Force
$gs = (Get-Item (Join-Path $dist "NetRadar-1.0.0-win64.exe")).Length
$cs = (Get-Item (Join-Path $dist "netradar-cli-1.0.0-win64.exe")).Length
Write-Host ("   GUI {0:N0} bytes / CLI {1:N0} bytes" -f $gs, $cs)
if ($gs -eq $cs) { throw "GUI and CLI artifacts are identical - copy failed" }

if ($Ndk -eq "") {
    Write-Host "`n[!] NDK not found, skip Android build" -ForegroundColor Yellow
    return
}

Write-Host "`n==> [2/3] build Android arm64 engine" -ForegroundColor Cyan
Push-Location $Root
cargo build --release -p netradar --target aarch64-linux-android
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "android build failed" }
Pop-Location

Write-Host "`n==> [3/3] package signed APK" -ForegroundColor Cyan
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "build\build_apk.ps1") 2>&1 |
    Select-String -Pattern "^(==>|   |Verifies)" | ForEach-Object { Write-Host $_.Line }

Write-Host "`n==> artifacts in $dist" -ForegroundColor Green
Get-ChildItem $dist | Select-Object Name, Length | Format-Table -AutoSize

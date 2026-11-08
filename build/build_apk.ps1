# NetRadar APK 构建脚本（不依赖 Gradle：aapt2 + javac + d8 + zipalign + apksigner）
param(
    [string]$Sdk = $env:ANDROID_HOME,
    [string]$Jdk = $env:JAVA_HOME,
    [switch]$SkipNative
)
if ([string]::IsNullOrWhiteSpace($Sdk)) { $Sdk = "C:\Users\$env:USERNAME\AppData\Local\Android\android-sdk" }
if ([string]::IsNullOrWhiteSpace($Jdk)) { $Jdk = "C:\Program Files\Java\jdk-17" }
if (-not (Test-Path (Join-Path $Sdk "platforms\android-29\android.jar"))) {
    throw "未找到 Android SDK（android-29）：请设置 ANDROID_HOME 或传 -Sdk 参数。当前: $Sdk"
}
if (-not (Test-Path (Join-Path $Jdk "bin\javac.exe"))) {
    throw "未找到 JDK：请设置 JAVA_HOME 或传 -Jdk 参数。当前: $Jdk"
}

$ErrorActionPreference = "Continue"
$root = (Split-Path -Parent $PSScriptRoot)
$proj = Join-Path $root "android"
$bt = Join-Path $Sdk "build-tools\29.0.3"
$androidJar = Join-Path $Sdk "platforms\android-29\android.jar"
$java = Join-Path $Jdk "bin\java.exe"
$javac = Join-Path $Jdk "bin\javac.exe"
$keytool = Join-Path $Jdk "bin\keytool.exe"
$out = Join-Path $root "dist"
$work = Join-Path $root "build\apk"
$ks = Join-Path $root "build\netradar.keystore"
$ksPass = "netradar2026"

New-Item -ItemType Directory -Force $out, $work, (Join-Path $work "gen") | Out-Null

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# 0) 拷贝 Rust 引擎（arm64 可执行文件，伪装成 .so 以随 APK 解压）
Step "准备原生引擎"
$engine = Join-Path $root "target\aarch64-linux-android\release\netradar-cli"
$libDir = Join-Path $work "lib\arm64-v8a"
New-Item -ItemType Directory -Force $libDir | Out-Null
Copy-Item $engine (Join-Path $libDir "libnetradar.so") -Force
Write-Host ("   engine: {0:N0} bytes" -f (Get-Item (Join-Path $libDir "libnetradar.so")).Length)

# 1) 编译资源
Step "aapt2 compile"
$resZip = Join-Path $work "res.zip"
Remove-Item $resZip -ErrorAction SilentlyContinue
& (Join-Path $bt "aapt2.exe") compile --dir (Join-Path $proj "res") -o $resZip
if ($LASTEXITCODE -ne 0) { throw "aapt2 compile 失败" }

# 2) 链接资源 + 生成 R.java
Step "aapt2 link"
$baseApk = Join-Path $work "base.apk"
Remove-Item $baseApk -ErrorAction SilentlyContinue
& (Join-Path $bt "aapt2.exe") link -o $baseApk -I $androidJar `
    --manifest (Join-Path $proj "AndroidManifest.xml") `
    --java (Join-Path $work "gen") `
    --min-sdk-version 24 --target-sdk-version 29 `
    --version-code 1 --version-name "1.0.0" `
    $resZip
if ($LASTEXITCODE -ne 0) { throw "aapt2 link 失败" }

# 3) 编译 Java
Step "javac"
$classes = Join-Path $work "classes"
Remove-Item $classes -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $classes | Out-Null
$srcs = @()
$srcs += Get-ChildItem -Recurse -Filter *.java (Join-Path $proj "src") | ForEach-Object { $_.FullName }
$srcs += Get-ChildItem -Recurse -Filter *.java (Join-Path $work "gen") | ForEach-Object { $_.FullName }
$argFile = Join-Path $work "javac_sources.txt"
($srcs | ForEach-Object { '"' + ($_ -replace '\\', '\\') + '"' }) | Set-Content $argFile -Encoding ascii
& $javac --release 8 -nowarn -encoding UTF-8 -cp $androidJar -d $classes "@$argFile"
if ($LASTEXITCODE -ne 0) { throw "javac 失败" }

# 4) dex
Step "d8"
$dexDir = Join-Path $work "dex"
Remove-Item $dexDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $dexDir | Out-Null
$classFiles = Get-ChildItem -Recurse -Filter *.class $classes | ForEach-Object { $_.FullName }
Write-Host ("   classes: {0}" -f $classFiles.Count)
& $java -cp (Join-Path $bt "lib\d8.jar") com.android.tools.r8.D8 --release --min-api 24 `
    --lib $androidJar --output $dexDir @classFiles
if ($LASTEXITCODE -ne 0) { throw "d8 失败" }

# 5) 打包：dex + so 塞进 base.apk
Step "打包 APK"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($baseApk, 'Update')
foreach ($entry in @(@("classes.dex", (Join-Path $dexDir "classes.dex")),
                     @("lib/arm64-v8a/libnetradar.so", (Join-Path $libDir "libnetradar.so")))) {
    $name = $entry[0]
    $file = $entry[1]
    $old = $zip.GetEntry($name)
    if ($old) { $old.Delete() }
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, $file, $name, [System.IO.Compression.CompressionLevel]::Optimal)
}
$zip.Dispose()

# 6) 对齐
Step "zipalign"
$aligned = Join-Path $work "aligned.apk"
Remove-Item $aligned -ErrorAction SilentlyContinue
& (Join-Path $bt "zipalign.exe") -f -p 4 $baseApk $aligned
if ($LASTEXITCODE -ne 0) { throw "zipalign 失败" }

# 7) 签名
Step "签名"
if (-not (Test-Path $ks)) {
    & $keytool -genkeypair -v -keystore $ks -alias netradar -keyalg RSA -keysize 2048 `
        -validity 10000 -storepass $ksPass -keypass $ksPass `
        -dname "CN=NetRadar, OU=Mobile, O=NetRadar, L=Kaifeng, ST=Henan, C=CN" 2>&1 | Out-Null
    if (-not (Test-Path $ks)) { throw "keystore 生成失败" }
}
$apk = Join-Path $out "NetRadar-1.0.0-arm64.apk"
Remove-Item $apk -ErrorAction SilentlyContinue
$apksigner = Join-Path $bt "lib\apksigner.jar"
& $java -jar $apksigner sign --ks $ks --ks-pass "pass:$ksPass" --key-pass "pass:$ksPass" `
    --v1-signing-enabled true --v2-signing-enabled true --out $apk $aligned
if ($LASTEXITCODE -ne 0) { throw "apksigner 签名失败" }
& $java -jar $apksigner verify --verbose $apk
if ($LASTEXITCODE -ne 0) { throw "签名校验失败" }

Write-Host "`n签名后的 APK: $apk" -ForegroundColor Green
Write-Host ("大小: {0:N2} MB" -f ((Get-Item $apk).Length / 1MB)) -ForegroundColor Green

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""截取 NetRadar 主窗口（PrintWindow），保存为 PNG。零第三方依赖。"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import zlib

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

PW_RENDERFULLCONTENT = 0x00000002


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD),
        ("biWidth", wt.LONG),
        ("biHeight", wt.LONG),
        ("biPlanes", wt.WORD),
        ("biBitCount", wt.WORD),
        ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD),
        ("biXPelsPerMeter", wt.LONG),
        ("biYPelsPerMeter", wt.LONG),
        ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def write_png(path, width, height, rgb_rows):
    raw = bytearray()
    for row in rgb_rows:
        raw.append(0)
        raw.extend(row)

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


def capture(title_substr, out):
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass
    hwnd = user32.FindWindowW(None, None)
    found = 0
    # 枚举所有顶层窗口
    EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(h, lp):
        nonlocal found
        n = user32.GetWindowTextLengthW(h)
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(h, buf, n + 1)
        if title_substr in buf.value and user32.IsWindowVisible(h):
            found = h
            return False
        return True

    user32.EnumWindows(EnumProc(cb), 0)
    if not found:
        print("window not found")
        return 1

    rect = wt.RECT()
    user32.GetWindowRect(found, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    if w <= 0 or h <= 0:
        print("bad size")
        return 1

    hdc = user32.GetWindowDC(found)
    mem = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    old = gdi32.SelectObject(mem, bmp)
    ok = user32.PrintWindow(found, mem, PW_RENDERFULLCONTENT)
    print("PrintWindow:", ok, "size:", w, h)

    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    lines = gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bmi), 0)
    print("GetDIBits lines:", lines)

    rows = []
    for y in range(h):
        off = y * w * 4
        row = bytearray(w * 3)
        src = buf.raw[off:off + w * 4]
        for x in range(w):
            b, g, r = src[x * 4], src[x * 4 + 1], src[x * 4 + 2]
            row[x * 3] = r
            row[x * 3 + 1] = g
            row[x * 3 + 2] = b
        rows.append(row)

    gdi32.SelectObject(mem, old)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(found, hdc)

    write_png(out, w, h, rows)
    print("saved", out)
    return 0


if __name__ == "__main__":
    title = sys.argv[1] if len(sys.argv) > 1 else "NetRadar"
    out = sys.argv[2] if len(sys.argv) > 2 else "shot.png"
    sys.exit(capture(title, out))

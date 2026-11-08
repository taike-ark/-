// 调试 GetAdaptersInfo 返回码与缓冲区布局
use std::os::raw::{c_char, c_void};
use std::ptr;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(n: *const c_char) -> *mut c_void;
    fn GetProcAddress(h: *mut c_void, n: *const c_char) -> *mut c_void;
}

type FnGetAdaptersInfo = unsafe extern "system" fn(*mut c_void, *mut u32) -> u32;
type FnGetIpAddrTable = unsafe extern "system" fn(*mut c_void, *mut u32, i32) -> u32;

fn main() {
    unsafe {
        let h = LoadLibraryA(b"iphlpapi.dll\0".as_ptr() as *const c_char);
        println!("iphlpapi handle = {:?}", h);
        let p = GetProcAddress(h, b"GetAdaptersInfo\0".as_ptr() as *const c_char);
        println!("GetAdaptersInfo = {:?}", p);
        if !p.is_null() {
            let f: FnGetAdaptersInfo = std::mem::transmute(p);
            let mut size: u32 = 0;
            let rc = f(ptr::null_mut(), &mut size);
            println!("first call rc = {} size = {}", rc, size);
            if size > 0 && size < 8_000_000 {
                let mut buf = vec![0u8; size as usize + 64];
                let rc2 = f(buf.as_mut_ptr() as *mut c_void, &mut size);
                println!("second call rc = {} size = {}", rc2, size);
                if rc2 == 0 {
                    let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    println!("ComboIndex as u32 = {}", n);
                    println!("first 64 bytes: {:02X?}", &buf[..64]);
                    // 打印 AdapterName / Description
                    let s = |off: usize, len: usize| {
                        let sl = &buf[off..off + len];
                        let end = sl.iter().position(|&c| c == 0).unwrap_or(sl.len());
                        String::from_utf8_lossy(&sl[..end]).to_string()
                    };
                    println!("AdapterName@12 = {:?}", s(12, 260));
                    println!("Description@272 = {:?}", s(272, 132));
                    println!("AddressLen@404 = {}", u32::from_ne_bytes([buf[404], buf[405], buf[406], buf[407]]));
                    println!("Address@408 = {:02X?}", &buf[408..416]);
                    println!("Index@416 = {}", u32::from_ne_bytes([buf[416], buf[417], buf[418], buf[419]]));
                    println!("IpAddress@448 = {:?}", s(448, 16));
                    println!("IpMask@464 = {:?}", s(464, 16));
                    println!("Gateway@496 = {:?}", s(496, 16));
                }
            }
        }
        let p2 = GetProcAddress(h, b"GetIpAddrTable\0".as_ptr() as *const c_char);
        if !p2.is_null() {
            let f2: FnGetIpAddrTable = std::mem::transmute(p2);
            let mut size: u32 = 0;
            let rc = f2(ptr::null_mut(), &mut size, 0);
            println!("GetIpAddrTable first rc = {} size = {}", rc, size);
        }
    }
}

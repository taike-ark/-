use std::os::raw::{c_char, c_void};
#[link(name="kernel32")] extern "system" { fn LoadLibraryA(n:*const c_char)->*mut c_void; fn GetProcAddress(h:*mut c_void,n:*const c_char)->*mut c_void; }
type FIE = unsafe extern "system" fn(*mut c_void)->u32;
fn u32at(b:&[u8],o:usize)->u32{ u32::from_ne_bytes([b[o],b[o+1],b[o+2],b[o+3]]) }
fn main(){ unsafe{
  let h=LoadLibraryA(b"iphlpapi.dll\0".as_ptr() as *const c_char);
  let f:FIE=std::mem::transmute(GetProcAddress(h,b"GetIfEntry\0".as_ptr() as *const c_char));
  for idx in [30u32,1,11,18,26,47,19] {
     let mut bvec=vec![0u8;1024];
     bvec[512..516].copy_from_slice(&idx.to_ne_bytes());
     let rc=f(bvec.as_mut_ptr() as *mut c_void);
     let name:String = if rc==0 { let mut v=Vec::new(); for i in 0..255 { let off=i*2; let w=u16::from_ne_bytes([bvec[off],bvec[off+1]]); if w==0 {break} v.push(w) } String::from_utf16_lossy(&v) } else { String::new() };
     let maclen=u32at(&bvec,528);
     println!("idx={} rc={} name={:?} maclen={} mac={:02X?}", idx, rc, name, maclen, &bvec[532..538]);
  }
}}

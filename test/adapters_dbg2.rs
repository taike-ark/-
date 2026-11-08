use std::os::raw::{c_char, c_void};
use std::ptr;
#[link(name="kernel32")] extern "system" { fn LoadLibraryA(n:*const c_char)->*mut c_void; fn GetProcAddress(h:*mut c_void,n:*const c_char)->*mut c_void; }
type FA = unsafe extern "system" fn(*mut c_void,*mut u32)->u32;
type FT = unsafe extern "system" fn(*mut c_void,*mut u32,i32)->u32;
fn u32at(b:&[u8],o:usize)->u32{ u32::from_ne_bytes([b[o],b[o+1],b[o+2],b[o+3]]) }
fn cs(b:&[u8],o:usize,l:usize)->String{ let s=&b[o..o+l]; let e=s.iter().position(|&c|c==0).unwrap_or(s.len()); String::from_utf8_lossy(&s[..e]).to_string() }
fn main(){ unsafe{
  let h=LoadLibraryA(b"iphlpapi.dll\0".as_ptr() as *const c_char);
  let fa:FA=std::mem::transmute(GetProcAddress(h,b"GetAdaptersInfo\0".as_ptr() as *const c_char));
  let ft:FT=std::mem::transmute(GetProcAddress(h,b"GetIpAddrTable\0".as_ptr() as *const c_char));
  let mut size:u32=0; fa(ptr::null_mut(),&mut size);
  let mut buf=vec![0u8;size as usize+64];
  let rc=fa(buf.as_mut_ptr() as *mut c_void,&mut size);
  println!("adapters rc={} size={}",rc,size);
  let mut off=0usize; let mut g=0;
  while off+592<=buf.len() && g<64 { g+=1;
    let next=(u32at(&buf,off) as u64)|((u32at(&buf,off+4) as u64)<<32);
    println!("  [{}] idx={} desc={:?} mac={:02X?} ip={:?} gw={:?}",
      g, u32at(&buf,off+416), cs(&buf,off+272,132), &buf[off+408..off+414],
      cs(&buf,off+448,16), cs(&buf,off+496,16));
    if next==0 {break} off=next as usize;
  }
  let mut s2:u32=0; ft(ptr::null_mut(),&mut s2,0);
  let mut t=vec![0u8; s2 as usize+64]; let rc2=ft(t.as_mut_ptr() as *mut c_void,&mut s2,0);
  let n=u32at(&t,0) as usize;
  println!("ipaddrtable rc={} n={}",rc2,n);
  for i in 0..n { let o=4+i*24;
    let ip=u32::from_be(u32at(&t,o)); let idx=u32at(&t,o+4); let m=u32::from_be(u32at(&t,o+8));
    println!("  row{} ip={}.{}.{}.{} idx={} mask=0x{:08X}", i, ip>>24,(ip>>16)&255,(ip>>8)&255,ip&255, idx, m);
  }
}}

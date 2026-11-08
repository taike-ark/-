use std::os::raw::{c_char, c_void};
use std::ptr;
#[link(name="kernel32")] extern "system" { fn LoadLibraryA(n:*const c_char)->*mut c_void; fn GetProcAddress(h:*mut c_void,n:*const c_char)->*mut c_void; }
type FAA = unsafe extern "system" fn(u32,u32,*mut c_void,*mut c_void,*mut u32)->u32;
fn u32at(b:&[u8],o:usize)->u32{ u32::from_ne_bytes([b[o],b[o+1],b[o+2],b[o+3]]) }
fn u64at(b:&[u8],o:usize)->u64{ let mut x=[0u8;8]; x.copy_from_slice(&b[o..o+8]); u64::from_ne_bytes(x) }
fn wide(b:&[u8],o:usize)->String{ let p=u64at(b,o) as usize; if p<0x1000 {return String::new()}
  unsafe{ let w=p as *const u16; let mut n=0; while n<512 && *w.add(n)!=0 {n+=1;} String::from_utf16_lossy(std::slice::from_raw_parts(w,n)) } }
fn main(){ unsafe{
  let h=LoadLibraryA(b"iphlpapi.dll\0".as_ptr() as *const c_char);
  let f:FAA=std::mem::transmute(GetProcAddress(h,b"GetAdaptersAddresses\0".as_ptr() as *const c_char));
  let mut size:u32=32768; let mut buf=vec![0u8;size as usize];
  let mut rc=f(2,0x0E,ptr::null_mut(),buf.as_mut_ptr() as *mut c_void,&mut size);
  println!("rc1={} size={}",rc,size);
  if rc==111 || rc==122 { buf=vec![0u8;size as usize+1024]; rc=f(2,0x0E,ptr::null_mut(),buf.as_mut_ptr() as *mut c_void,&mut size); println!("rc2={} size={}",rc,size); }
  let mut off=0usize; let mut g=0;
  while off+200<=buf.len() && g<64 { g+=1;
    let next=u64at(&buf,off+8) as usize;
    let idx=u32at(&buf,off+4);
    let maclen=u32at(&buf,off+88);
    println!("[{}] off={} next={} idx={} len={} name={:?} desc={:?} maclen={} oper={}",
      g, off, next, idx, u32at(&buf,off), wide(&buf,off+72), wide(&buf,off+64), maclen, u32at(&buf,off+104));
    if next==0 || next>=buf.len() { println!("  stop: next out of range"); break }
    off=next;
  }
}}

#![feature(addr_parse_ascii)]

use netaddr2::{Contains, Netv6Addr};
use serde::Deserialize;
use std::{
    ffi::CString,
    net::{IpAddr::V6, Ipv4Addr, SocketAddr},
};

#[derive(Deserialize)]
struct Config {
    headers: Vec<String>,
    networks: Vec<Netv6Addr>,
}

mod raw {
    use std::os::raw::c_char;
    #[link(wasm_import_module = "http_handler")]
    extern "C" {
        pub fn log(level: i32, ptr: *const c_char, len: i32);
        pub fn get_config(ptr: *mut c_char, len: i32) -> i32;
        pub fn get_source_addr(ptr: *mut c_char, len: i32) -> i32;
        pub fn set_header_value(kind: i32, name: *const c_char, name_len: i32, value: *const c_char, value_len: i32);
    }
}
fn error(s: &str) {
    let s = CString::new(s).unwrap();
    unsafe { raw::log(2, s.as_ptr(), s.count_bytes() as i32); };
}

fn get_config() -> String {
    let mut v = vec![0; u8::MAX as usize];
    let ptr = v.as_mut_ptr() as *mut i8;
    let len = v.len();
    let len = unsafe { raw::get_config(ptr, len as i32) };
    v.truncate(len as usize);
    String::from_utf8(v).unwrap()
}

fn get_source_addr() -> SocketAddr {
    let mut v = vec![0; u8::MAX as usize];
    let ptr = v.as_mut_ptr() as *mut i8;
    let len = v.len();
    let len = unsafe { raw::get_source_addr(ptr, len as i32) };
    v.truncate(len as usize);
    SocketAddr::parse_ascii(&v).unwrap()
}

fn set_header_value(name: &str, value: &str) {
    let name = CString::new(name).unwrap();
    let value = CString::new(value).unwrap();
    unsafe { raw::set_header_value(0, name.as_ptr(), name.count_bytes() as i32, value.as_ptr(), value.count_bytes() as i32); };
}

#[no_mangle]
pub extern "C" fn handle_request() -> i64 {
    if let V6(ip) = get_source_addr().ip() {
        let config: Config = match serde_json::from_str(&get_config()) {
            Ok(c) => c,
            Err(err) => {
                error(&format!("{}", err));
                return 1;
            }
        };
        for network in config.networks {
            if network.contains(&ip) {
                let octets: [u8; 4] = ip.octets()[12..16].try_into().unwrap();
                let ip = Ipv4Addr::from(octets).to_string();
                for header in config.headers {
                    set_header_value(&header, &ip);
                }
                break;
            }
        }
    }
    1
}

#[no_mangle]
pub extern "C" fn handle_response(_req_ctx: i32, _is_error: i32) {}


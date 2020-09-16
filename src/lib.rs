#![no_std]
use core::ffi;
use libc;

const SELF: &str = "/proc/self/maps\0";

unsafe fn find_in_mem_file(mem_file: *mut libc::FILE, main_ptr: usize) -> Option<(*mut ffi::c_void, usize)> {
    let page_len = 4096; // Seems to be enough
    let mut buf = [0u8; 4096];
    while ! libc::fgets(buf.as_mut_ptr() as _, page_len, mem_file).is_null() {
        let mut start: libc::size_t = 0;
        let mut end: libc::size_t = 0;
        // TODO check it contains newline
        if libc::sscanf(
            buf.as_mut_ptr() as _,
            "%p-%p \0".as_ptr() as _,
            &mut start as *mut libc::size_t,
            &mut end as *mut libc::size_t
        ) == 2 && start <= main_ptr && main_ptr < end {
            return Some((start as _, end - start))
        }
    }
    
    None
}

#[no_mangle]
pub extern "C" fn remap_process_binary(main_ptr: *const ffi::c_void) -> libc::c_int {
    unsafe {
        if ! libc::getenv("LIBREMAP_DISABLE\0".as_ptr() as _).is_null() {
            return 1;
        }
        let mem_file = libc::fopen(SELF.as_ptr() as _, "r\0".as_ptr() as _);
        if mem_file == ((-1isize) as usize as _) {
            // errno is set by fopen
            return -1;
        }
        
        let range = find_in_mem_file(mem_file, main_ptr as usize);

        if libc::fclose(mem_file) != 0 {
            // errno is set by fclose
            return -1;
        }

        if let Some((code_mem, size)) = range {
            let buffer = libc::malloc(size);
            if buffer.is_null() {
                // errno is set by malloc
                return -1;
            }
            libc::memcpy(buffer, code_mem, size);
            if libc::munmap(code_mem, size) != 0 {
                // errno is set by munmap
                return -1;
            }
            if libc::mmap(
                code_mem, size, libc::PROT_WRITE | libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1, 0
            ) != code_mem {
                // One could return -1, "but there's nobody home", as
                // return address is not valid after unmap.
                let msg = "ERROR:libremap: failed to map same range again; re-run with LIBREMAP_DISABLE environment variable; exiting with code 42...\n\0";
                libc::write(1, msg.as_ptr() as _, msg.as_bytes().len() - 1);
                // libc::exit doesn't work here
                libc::_exit(42);
            }
            libc::memcpy(code_mem, buffer, size);
            if libc::mprotect(code_mem, size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                // One could return -1, "but there's nobody home", as
                // return address is not executable
                let msg = "ERROR:libremap: failed to make range executable again; re-run with LIBREMAP_DISABLE environment variable; exiting with code 42...\n\0";
                libc::write(1, msg.as_ptr() as _, msg.as_bytes().len() - 1);
                // libc::exit doesn't work here
                libc::_exit(42);
            }
            if libc::madvise(code_mem, size, libc::MADV_HUGEPAGE) != 0 {
                // errno is set by madvise
                return -1;
            }
            libc::free(buffer);
            0
        } else {
            // Does better code exists?
            *libc::__errno_location() = libc::EFAULT;
            -1
        }
    }
}

// An obligatory no_std panic_handler.
#[panic_handler]
fn dont_panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { libc::exit(42) }
}

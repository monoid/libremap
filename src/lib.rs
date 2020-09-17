#![no_std]
use libc;

// C-string of /proc file that contains memory regions mapping info.
const SELF: &str = "/proc/self/maps\0";

unsafe fn write_str(handle: libc::c_int, msg: &str) {
    libc::write(
        handle,
        msg.as_ptr() as *const libc::c_void,
        msg.as_bytes().len(),
    );
}

enum Error {
    Recoverable {
        retval: libc::c_int,
        errno: Option<libc::c_int>,
    },
    Fatal(&'static str),
}

impl Error {
    fn error(retval: libc::c_int) -> Self {
        Self::Recoverable {
            retval,
            errno: None,
        }
    }

    fn error_errno(retval: libc::c_int, errno: libc::c_int) -> Self {
        Self::Recoverable {
            retval,
            errno: Some(errno),
        }
    }

    fn fatal(msg: &'static str) -> Self {
        Self::Fatal(msg)
    }
}

unsafe fn check_disabled() -> Result<(), Error> {
    if libc::getenv("LIBREMAP_DISABLE\0".as_ptr() as _).is_null() {
        Ok(())
    } else {
        Err(Error::error(1))
    }
}

unsafe fn find_in_open_mem_file(
    mem_file: *mut libc::FILE,
    main_ptr: usize,
) -> Option<(*mut libc::c_void, usize)> {
    let mut buf = [0u8; 4096];
    let page_len = buf.len() as libc::c_int;

    // If fgets will fail in any fashion, we will return None...
    while !libc::fgets(buf.as_mut_ptr() as _, page_len, mem_file).is_null() {
        let mut start: libc::size_t = 0;
        let mut end: libc::size_t = 0;
        // TODO check it contains newline.  fgets always writes \0.
        if libc::sscanf(
            buf.as_mut_ptr() as _,
            "%p-%p \0".as_ptr() as _,
            &mut start as *mut libc::size_t,
            &mut end as *mut libc::size_t,
        ) == 2
            && start <= main_ptr
            && main_ptr < end
        {
            return Some((start as _, end - start));
        }
    }

    None
}

unsafe fn find_in_mem_file(
    main_ptr: *const libc::c_void,
) -> Result<Option<(*mut libc::c_void, usize)>, Error> {
    let mem_file = libc::fopen(SELF.as_ptr() as _, "r\0".as_ptr() as _);
    if mem_file == ((-1isize) as usize as _) {
        // errno is set by fopen
        return Err(Error::error(-1));
    }

    let range = find_in_open_mem_file(mem_file, main_ptr as usize);

    if libc::fclose(mem_file) != 0 {
        // errno is set by fclose
        return Err(Error::error(-1));
    }

    Ok(range)
}

unsafe fn remap_process_binary_impl(main_ptr: *const libc::c_void) -> Result<(), Error> {
    check_disabled()?;

    let range = find_in_mem_file(main_ptr)?;

    if let Some((code_mem, size)) = range {
        let buffer = libc::malloc(size);
        if buffer.is_null() {
            // errno is set by malloc
            return Err(Error::error(-1));
        }
        libc::memcpy(buffer, code_mem, size);
        if libc::munmap(code_mem, size) != 0 {
            // errno is set by munmap
            return Err(Error::error(-1));
        }
        if libc::mmap(
            code_mem,
            size,
            libc::PROT_WRITE | libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        ) != code_mem
        {
            // Return address is not executable, so signal fatal error.
            return Err(Error::fatal("failed to map same range again"));
        }
        libc::memcpy(code_mem, buffer, size);
        if libc::mprotect(code_mem, size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
            // Return address is not executable, so signal fatal error.
            return Err(Error::fatal("failed to make range executable again"));
        }
        if libc::madvise(code_mem, size, libc::MADV_HUGEPAGE) != 0 {
            // errno is set by madvise
            return Err(Error::error(-1));
        }
        libc::free(buffer);
        Ok(())
    } else {
        Err(Error::error_errno(-1, libc::EFAULT))
    }
}

#[no_mangle]
pub unsafe extern "C" fn remap_process_binary(main_ptr: *const libc::c_void) -> libc::c_int {
    match remap_process_binary_impl(main_ptr) {
        Ok(_) => 0,
        Err(Error::Recoverable {
            retval,
            errno: maybe_errno,
        }) => {
            if let Some(errno) = maybe_errno {
                *libc::__errno_location() = errno;
            }
            retval
        }
        Err(Error::Fatal(msg)) => {
            let stderr = 1;
            let prefix = "FATAL:libremap ";
            let instruction =
                "re-run with LIBREMAP_DISABLE environment variable; exiting with code 42...\n";

            write_str(stderr, prefix);
            write_str(stderr, msg);
            write_str(stderr, instruction);
            // libc::exit doesn't work on fatal errors, as it calls
            // atexit and friends.
            libc::_exit(42)
        }
    }
}

// An obligatory no_std panic_handler.
#[panic_handler]
fn dont_panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { libc::exit(42) }
}

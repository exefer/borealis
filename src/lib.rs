use std::ffi::{CStr, CString};

use libc::{PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_NEXT, _SC_PAGESIZE};

/// Apply mprotect to the pages covering [addr, addr+len), aligning to page boundaries
unsafe fn mprotect_pages(addr: *mut u8, len: usize, prot: libc::c_int) {
    let page_size = libc::sysconf(_SC_PAGESIZE) as usize;
    let start = addr as usize;
    // Round start down to page boundary
    let page_start = start & !(page_size - 1);
    // Round end up to page boundary
    let page_end = (start + len + page_size - 1) & !(page_size - 1);
    let result = libc::mprotect(page_start as *mut libc::c_void, page_end - page_start, prot);
    assert_eq!(result, 0, "mprotect failed: {}", *libc::__errno_location());
}

/// Make memory region readable, writable, and executable
unsafe fn make_memory_rwx(addr: *mut u8, len: usize) {
    mprotect_pages(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

/// Restore memory region to read + execute only
unsafe fn make_memory_rx(addr: *mut u8, len: usize) {
    mprotect_pages(addr, len, PROT_READ | PROT_EXEC);
}

/// Overwrite memory at `addr` with `patch`
unsafe fn patch_memory<const N: usize>(addr: *mut u8, patch: &[u8; N]) {
    make_memory_rwx(addr, N);
    std::ptr::copy_nonoverlapping(patch.as_ptr(), addr, N);
    make_memory_rx(addr, N);
}

/// Look up symbol in the current process (dlsym)
unsafe fn find_symbol(name: &str) -> *mut u8 {
    let cname = CString::new(name).unwrap();
    let ptr = libc::dlsym(RTLD_NEXT, cname.as_ptr());
    assert!(!ptr.is_null(), "symbol not found");
    ptr as *mut u8
}

pub struct Module {
    pub base: usize,
    pub size: usize,
}

/// Returns the base address and total size of the main executable
unsafe fn find_main_module() -> Option<Module> {
    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let out = &mut *(data as *mut Option<Module>);
        let info_ref = &*info;

        // Only consider main executable (dlpi_name is empty string)
        let name = if info_ref.dlpi_name.is_null() {
            &b""[..]
        } else {
            CStr::from_ptr(info_ref.dlpi_name).to_bytes()
        };
        if !name.is_empty() {
            return 0; // skip shared libraries
        }

        // Find the lowest base and highest end among PT_LOAD segments
        let mut min_base = usize::MAX;
        let mut max_end = 0usize;

        for i in 0..info_ref.dlpi_phnum {
            let phdr = info_ref.dlpi_phdr.add(i as usize);
            if (*phdr).p_type == libc::PT_LOAD {
                let seg_base = info_ref.dlpi_addr as usize + (*phdr).p_vaddr as usize;
                let seg_end = seg_base + (*phdr).p_memsz as usize;

                if seg_base < min_base {
                    min_base = seg_base;
                }
                if seg_end > max_end {
                    max_end = seg_end;
                }
            }
        }

        if min_base < max_end {
            *out = Some(Module {
                base: min_base,
                size: max_end - min_base,
            });
            return 1; // stop iteration
        }

        0
    }

    let mut module: Option<Module> = None;

    libc::dl_iterate_phdr(Some(callback), &mut module as *mut _ as *mut libc::c_void);

    module
}

// Auto-run on library load
#[used]
#[link_section = ".init_array"]
static INIT: unsafe extern "C" fn() = init;

unsafe extern "C" fn init() {
    eprintln!("libborealis loaded");

    let module = find_main_module().unwrap();

    let first_match_offset = 0x5638;
    let first_match_addr = (module.base + first_match_offset) as *mut u8;

    patch_memory(first_match_addr, &[0x64; 0x2A]);
}

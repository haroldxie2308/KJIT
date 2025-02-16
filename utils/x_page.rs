use core::arch::asm;
use core::ptr;
use alloc::fmt::Debug;
use kernel::alloc::Flags;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;

extern "C" {
	fn uca_vmalloc(size: usize) -> *mut u8;
	fn uca_vcalloc(nmemb: usize, size: usize) -> *mut u8;
	fn uca_vrealloc(ptr: *mut u8, size: usize) -> *mut u8;
	fn uca_vfree(ptr: *mut u8);
	fn set_memory_x(addr: core::ffi::c_ulong, numpages: core::ffi::c_int);
	// fn set_memory_nx
}

static NR_EXTRA_PAGE: usize = 10;

/// `XPage` is a wrapper struct around executable page(s), allocated with vmalloc
/// and is usually constructed from a `Vec<u8>` by calling `XPage::from_vec()`.
/// 
/// Will be automatically dropped when going out of scope.
pub(crate) struct XPage {
	page_ptr: *mut u8,
	page_num: usize,
	len: usize,
}

impl Debug for XPage {
	fn fmt(&self, f: &mut alloc::fmt::Formatter<'_>) -> alloc::fmt::Result {
		writeln!(f, "XPage bytes: ")?;
		let mut cnt = 0;
		for i in 0..self.len {
			let byte = unsafe { *self.page_ptr.add(i) };
			write!(f, "{:02x} ", byte)?;
			cnt += 1;
			if cnt % 16 == 0 {
				writeln!(f, "")?;
			}
		}
		writeln!(f, "")?;
	    Ok(())
	}
}

impl Default for XPage {
	fn default() -> Self {
	    Self { page_ptr: core::ptr::null_mut(), page_num: 0, len: 0 }
	}
}

impl Drop for XPage {
	fn drop(&mut self) {
	    unsafe {
	    	uca_vfree(self.page_ptr);
	    }
	}
}

impl XPage {
	pub(crate) fn new() -> Self {
		Self {
			page_ptr: ptr::null_mut(),
			page_num: 0,
			len: 0,
		}
	}

	/// `flag` is only for consistency with other kernel interfaces
	pub(crate) fn with_capacity(page_num: usize, _flag: Flags) -> Result<Self> {
		let page_ptr = unsafe { uca_vmalloc(PAGE_SIZE * page_num) };
		if page_ptr.is_null() {
			Err(ENOMEM)
		} else {
			unsafe { set_memory_x(page_ptr as u64, page_num as i32); }
			Ok(Self {
				page_ptr,
				page_num,
				len: 0,
			})
		}
	}

	/// Returns the current size of machine code in bytes
	pub(crate) fn len(&self) -> usize {
		self.len
	}

	/// Returns a pointer to the beginning of executable machine code.
	pub(crate) fn as_ptr(&self) -> *const u8 {
		self.page_ptr
	}

	/// Create a new XPage from `&[u8]`.
	pub(crate) fn from_slice(src_vec: &[u8]) -> Self {
		let mut page_num = src_vec.len() / PAGE_SIZE + NR_EXTRA_PAGE;
	    let page_ptr = unsafe { uca_vmalloc(PAGE_SIZE * page_num) };
	    if page_ptr.is_null() {
	    	panic!("Convertion failed!");
	    } else {
	    	unsafe {
	    		for i in 0..src_vec.len() {
	    			let target_ptr = page_ptr.add(i);
	    			*target_ptr = src_vec[i];
	    		}
	    		set_memory_x(page_ptr as u64, page_num as i32);
	    	}
	    }
	    Self {
    		page_ptr,
    		page_num,
			len: src_vec.len(),
    	}
	}

	/// Appends newly translated code to the end of current executable code.
	pub(crate) fn append(&mut self, src_vec: &[u8]) {
		// Pre-append check
		if self.len() + src_vec.len() > self.page_num * PAGE_SIZE {
			pr_info!("XPage capacity exceeded, expanding...\n");

			let new_ptr = unsafe {
				uca_vrealloc(self.page_ptr, (self.page_num + 1) * PAGE_SIZE)
			};

			if new_ptr.is_null() {
				panic!("Unable to allocate new memory for xpage\n")
			} else {
				pr_info!("new_ptr: {:#x}\n", new_ptr as usize);
				self.page_ptr = new_ptr;
				self.page_num += 1;
				unsafe { set_memory_x(self.page_ptr as u64, self.page_num as i32); }
			}
		}

		unsafe {
			let append_ptr = self.page_ptr.add(self.len());
			for i in 0..src_vec.len() {
				let target_ptr = append_ptr.add(i);
				*target_ptr = src_vec[i];
			}
			// ! TEST: is this necessary? 
			asm!(
				"dc cvau, {dst}",
				"dsb ish",
				"ic ivau, {dst}",
				"dsb ish",
				"isb",
				dst = in(reg) append_ptr,
				options(nostack),
			);
		}
		self.len += src_vec.len();
	}

	/// Replaces bytes of one instruction starting at `offset` with `new_bytes`.
	/// Checks the alignement before replacement, flushes the cache before return.
	pub(crate) fn update_insn(&mut self, offset: usize, new_bytes: &[u8]) {
		if new_bytes.len() != 4 {
			pr_err!("Invalid new instruction bytes for update\n");
			return;
		} else if offset % 4 != 0 {
			pr_err!("Invalid offset for update\n");
			return;
		}
		unsafe {
			let src_ptr = new_bytes.as_ptr() as *const u32;
			let dst_ptr = self.page_ptr.add(offset) as *mut u32;

			// Credits: https://mariokartwii.com/armv8/ch30.html for hint on data cache and insn cache
			asm!(
				"ldr w0, [{src}]", 
				"str w0, [{dst}]", 
				"dc cvau, {dst}",
				"dsb ish",
				"ic ivau, {dst}",
				"dsb ish",
				"isb",
				src = in(reg) src_ptr, 
				dst = in(reg) dst_ptr,
				// We have clobbered w0
				out("w0") _,
				options(nostack),
			);
		}
	}
}

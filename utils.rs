use core::arch::asm;
use kernel::alloc::Flags;
use kernel::prelude::*;
use kernel::uaccess::*;
use kernel::pr_cont;

use crate::trans::cs_rust::prelude::*;

pub(crate) mod multi_map;
pub(crate) mod circ_buf;
pub(crate) mod x_page;

/// Reads `size` bytes userspace memory at `addr`
pub(super) fn read_mem(addr: u64, size: usize) -> Result<Vec<u8>> {
    let mut mem: Vec<u8> = Vec::new();

    let user_reader = UserSlice::new(addr as usize, size).reader();
    if let Ok(_) = user_reader.read_all(&mut mem, GFP_ATOMIC) {
    	Ok(mem)
    } else {
    	Err(EFAULT)
    }
}

/// Inserts bytes in `source` to `dst` at `idx`
pub(super) fn insert<T: Copy>(dst: &mut Vec<T>, src: &[T], idx: usize) -> Result<()> {
	if src.len() == 0 {
		return Ok(());
	}
	if idx == dst.len() { /* Appending */
		for i in 0..src.len() {
			dst.push(src[i], GFP_ATOMIC)?;
		}
		return Ok(());
	} else if idx < dst.len() { /* Inserting */
		if dst.try_reserve(src.len()).is_ok() {
    		let dst_ptr = dst.as_mut_ptr();
    		unsafe {
    			let mut i = dst_ptr.add(dst.len() - 1);
    			let mut j = dst_ptr.add(dst.len() + src.len() - 1);
    			for _ in 0..(dst.len() - idx) {
    				*j = *i;
    				i = i.sub(1);
    				j = j.sub(1);
    			}
    			dst.set_len(dst.len() + src.len());
    		}
    		for i in 0..src.len() {
    			dst[idx + i] = src[i];
    		}
    		return Ok(());
    	} else {
    		pr_err!("insert: Memory error\n");
    		return Err(ENOMEM);
    	}
	} else { /* Invalid param */
		pr_err!("insert: Invalid param\n");
		return Err(ERANGE);
	}
}

/// Appends bytes in `src` to the end of `dst`
pub(super) fn append<T: Copy>(dst: &mut Vec<T>, src: &[T]) -> Result<()> {
	let len = dst.len();
	insert(dst, src, len)
}

/// Pushes `insn_bytes` into `dst`, takes care of little endianness.
/// 
/// Do NOT use this function for normal push operations because it will reverse the byte order for endianness!
pub(super) fn push_insn(dst: &mut Vec<u8>, insn_bytes: u32) -> Result<()> {
	dst.push((insn_bytes >>  0) as u8, GFP_ATOMIC)?;
	dst.push((insn_bytes >>  8) as u8, GFP_ATOMIC)?;
	dst.push((insn_bytes >> 16) as u8, GFP_ATOMIC)?;
	dst.push((insn_bytes >> 24) as u8, GFP_ATOMIC)?;
	Ok(())
}

/// Replaces one insn in `ori` at `idx` by new insn(s) in `replacement`, operating in bytes, modification done in-place
pub(super) fn replace_insn(ori: &mut Vec<u8>, replacement: &[u8], idx: usize) -> Result<()> {
	if replacement.len() == 0 {
		// Removing the insn at `idx`
		for _ in 0..4 {
			ori.remove(idx);
		}
		Ok(())
	} else {
		for i in 0..4 {
			ori[idx + i] = replacement[i];
		}
		insert(ori, &replacement[4..], idx + 4);
		Ok(())
	}
}

/// Prints out the disassembly of the code section pointed to by `code_ptr`, `len` is in bytes
/// 
/// This function returns the disassemble results as well.
pub(super) fn print_disasm(code_ptr: *const u8, len: usize, pref: &str) -> Vec<*mut cs_insn> {
	let mut ret = Vec::new();
	let mut addr: u64 = 0;
	let mut code_ptr = code_ptr;
	let mut size = len;
	for _ in 0..(size / 4) {
		let ori_addr = addr;
		if let Ok(insn_ptr) = disasm_iter(
								&mut code_ptr as *mut *const u8,
								&mut size as *mut usize,
								&mut addr as *mut u64
		) {
			ret.push(insn_ptr, GFP_ATOMIC).unwrap();
			unsafe {
				match Insn::from((*insn_ptr).id) {
					Insn::ARM64_INS_INVALID => {
						pr_err!("{}Invalid Instruction\n", pref);
						break;
					}
					insn_type @ (Insn::ARM64_INS_B | Insn::ARM64_INS_BL) => {
						if let Op::IMM(b_target) = get_operand(insn_ptr, 0) {
							let b_target = b_target as u64;
							pr_info!("{}{:#04x?} - {:?} {:?} => {:#x?}\n", pref, ori_addr, insn_type, get_cc(insn_ptr), b_target);
						} else {
							pr_err!("Wrong B/BL operand\n");
						}
					}
					insn_type => {
						pr_info!("{}{:#04x?} - {:?}\n", pref, ori_addr, insn_type);
					}
				}
			}
		} else {
			pr_err!("{}print_disasm failed\n", pref);
			break;
		}
	}
	ret
}

pub(crate) fn print_bytes(ptr: *const u8, len: usize, pref: &str) {
	let mut cnt = 0;
	pr_info!("{}: ", pref);
	for i in 0..len {
		let byte = unsafe { *ptr.add(i) };
		pr_cont!("{:02x} ", byte);
		cnt += 1;
		if cnt % 256 == 0{
			pr_info!("{} con't: ", pref)
		}
	}
}

pub(crate) fn check_in<T: Eq>(set: &Vec<T>, elem: &T) -> bool {
	for i in 0..set.len() {
		if set[i] == *elem {
			return true;
		}
	}
	return false;
}

pub(crate) fn get_current_sp() {
	let curr_sp: u64;
	unsafe {
		asm!(
			"mov x0, sp",
			out("x0") curr_sp
		);
	}
	pr_info!("Current SP: {:#0x}\n", curr_sp);
}

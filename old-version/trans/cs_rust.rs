//! A wrapper module around `capstone_sys`, providing safe and easy to use APIs for ARM64 disassembly.

use core::sync::atomic::{AtomicPtr, Ordering};
use kernel::prelude::*;
use kernel::sync::Arc;
mod capstone_sys;
use capstone_sys::*;

pub(crate) mod prelude {
	pub(crate) use super::Insn;
	pub(crate) use super::OpType;
	pub(crate) use super::SysReg;
	
	pub(crate) use super::GLOBAL_CSH;
	pub(crate) use super::{disasm_iter, disasm_no_addr, disasm_one_preserve_addr, disasm_preserve_first_addr};
	pub(crate) use super::{free_insn, free_insns};
	pub(crate) use super::{Op, get_cc, get_operand, get_shift, get_op_cnt};
	pub(crate) use super::capstone_sys::{cs_insn, csh};
}

pub(crate) type Insn = capstone_sys::arm64_insn;
pub(crate) type OpType = capstone_sys::arm64_op_type;
pub(crate) type SysReg = capstone_sys::arm64_sysreg;
pub(crate) static GLOBAL_CSH: AtomicPtr<csh> = AtomicPtr::new(core::ptr::null_mut());

extern "C" {
	/// Uses C to initialize the capstone library in kernel
	fn kjit_cs_setup() -> bool;
	/// Uses C to get the operand of an insn
	fn kjit_cs_get_operand(insn: *mut cs_insn, idx: usize) -> u64;
	/// Uses C to get the condition code of an insn
	fn kjit_cs_get_cc(insn: *mut cs_insn) -> u32;
}

/// Creates a new capstone handle, MUST be called before any disassemble operations
fn open(csh_ptr: *mut csh) -> Result<(), u32> {
	unsafe {
		match cs_open(cs_arch::CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, csh_ptr) {
		    cs_err::CS_ERR_OK => {
		    	Ok(())
		    }
		    err => {
		        pr_err!("Capstone open failed, errno: {}\n", err);
		        Err(err)
		    }
		}
	}

}

/// Closes the Capstone handle pointed by `csh_ptr`
fn close(csh_ptr: *mut csh) -> Result<(), u32> {
	match unsafe {
		cs_close(csh_ptr)
	} {
		cs_err::CS_ERR_OK => Ok(()),
		err => Err(err),
	}
}

/// Iteratively disassambles the code block and returns a pointer to the disassembled `cs_insn`.
pub(crate) fn disasm_iter(code: *mut *const u8, size: *mut usize, addr: *mut u64) -> Result<*mut cs_insn, ()> {
	let handle = handle();
	unsafe {
		let insn = cs_malloc(handle);
		if cs_disasm_iter(
			handle,
			code,
			size,
			addr,
			insn
		) {
			Ok(insn)
		} else {
			Err(())
		}
	}
}

static NOP_BYTES: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];

/// This function disassembles `size` bytes of instructions pointed to by `code_ptr` and set all
/// result instruction to have address of 0.
pub(crate) fn disasm_no_addr(code_ptr: *const u8, size: usize) -> Result<Vec<*mut cs_insn>> {
	let mut ret = Vec::new();
	let mut code_ptr = code_ptr;
	let mut size = size;
	for _ in 0..(size / 4) {
        let mut addr = 0_u64;
		if let Ok(insn_ptr) = disasm_iter(
								&mut code_ptr as *mut *const u8,
								&mut size as *mut usize,
								&mut addr as *mut u64
		) {
			ret.push(insn_ptr, GFP_ATOMIC)?;
		} else {
			pr_warn!("disasm_no_addr failed, nop filled in for insn\n",);
			// crate::code_lifter::utils::print_bytes(code_ptr, 4, "disasm_no_addr");
			let mut code_ptr = NOP_BYTES.as_ptr();
			if let Ok(insn_ptr) = disasm_iter(
									&mut code_ptr as *mut *const u8,
									&mut size as *mut usize,
									&mut addr as *mut u64
			) {
				ret.push(insn_ptr, GFP_ATOMIC).unwrap();
			}
		}
	}
	Ok(ret)
}

/// This function is used to preserve immediate branching offset in CBNZ/CBZ/TBNZ/TBZ
pub(crate) fn disasm_one_preserve_addr(code_ptr: *const u8, original_addr: u64) -> Result<*mut cs_insn> {
	let mut addr = original_addr;
	let mut code_ptr = code_ptr;
	let mut size = 4_usize;
	if let Ok(insn_ptr) = disasm_iter(
							&mut code_ptr as *mut *const u8,
							&mut size as *mut usize,
							&mut addr as *mut u64
	) {
		Ok(insn_ptr)
	} else {
		Err(EFAULT)
	}
}

/// This function set the address of the first instruction to `original_addr` and 
/// those of the rest to 0.
pub(crate) fn disasm_preserve_first_addr(code_ptr: *const u8, size: usize, addr: u64) -> Result<Vec<*mut cs_insn>>{
    let mut ret = Vec::new();
    let first_insn_ptr = disasm_one_preserve_addr(code_ptr, addr)?;
    ret.push(first_insn_ptr, GFP_ATOMIC).unwrap();
    if size > 4 {
	    let remaining_insns = disasm_no_addr(unsafe {code_ptr.add(4)}, size - 4)?;
	    for i in 0..remaining_insns.len() {
	        ret.push(remaining_insns[i], GFP_ATOMIC).unwrap();
	    }
    }
    Ok(ret)
}

/// Memory allocated are pointed to by `*cs_insn` in the returned Vec and has to be freed MANUALLY.
fn disasm(code: &[u8], addr: u64, count: usize) -> Result<Vec<*mut cs_insn>> {
	let mut ret = Vec::new();
	let handle = handle();
	let mut code_ptr = code.as_ptr();
	let mut size = code.len();
	let mut addr = addr;
	for _ in 0..count {
		unsafe {
			let insn = cs_malloc(handle);
			if cs_disasm_iter(
				handle,
				&mut code_ptr as *mut *const u8,
				&mut size as *mut usize,
				&mut addr as *mut u64,
				insn
			) {
				ret.push(insn, GFP_ATOMIC).unwrap()
			} else {
				return Err(EFAULT);
			}
		}
	}

	Ok(ret)
}

/// Frees one `cs_insn`
pub(crate) fn free_insn(insn_ptr: *mut cs_insn) {
	unsafe {
		cs_free(insn_ptr, 1);
	}
}

/// Iteratively frees the insns passed in
pub(crate) fn free_insns(insns: &[*mut cs_insn]) {
	for i in 0..insns.len() {
		unsafe { cs_free(insns[i], 1); }
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
	REG(u32),
	IMM(i64),
	MEM(u32, u32, i32),
	FP,
	SYS(u32),
	INVAL,
}

/// Gets the `idx`th operand of an insn
pub(crate) fn get_operand(insn_ptr: *mut cs_insn, idx: usize) -> Op {
	unsafe {
		let op_type = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].type_;
		match op_type {
			OpType::ARM64_OP_REG => {
				let op_value = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].__bindgen_anon_1.reg;
				Op::REG(op_value)
			}
			OpType::ARM64_OP_IMM => {
				let op_value = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].__bindgen_anon_1.imm;
				Op::IMM(op_value)
			}
			OpType::ARM64_OP_MEM => {
				let op_value = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].__bindgen_anon_1.mem;
				Op::MEM(op_value.base, op_value.index, op_value.disp)
			}
			OpType::ARM64_OP_FP => {
				Op::FP
			}
			OpType::ARM64_OP_SYS => {
				let op_value = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].__bindgen_anon_1.reg;
				Op::SYS(op_value)
			}
			_ => {
				// For all other types, treats them as Invalid Op for now.
				Op::INVAL
			}
		}
	}
}

/// Gets the condition code of the insn, return value can be casted to `Cond` via `Cond::from(value)`.
pub(crate) fn get_cc(insn_ptr: *mut cs_insn) -> u32 {
	unsafe {
		kjit_cs_get_cc(insn_ptr)
	}
}

/// Gets the shift of the insn.
/// 
/// The first return value can be casted to `ShiftCls` via `ShiftCls::from(value)` and the second return value is the actual shift amount.
pub(crate) fn get_shift(insn_ptr: *mut cs_insn, idx: usize) -> (u32, u8) {
	unsafe {
		let shift = (*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].shift;
		(shift.type_ as u32, shift.value as u8)
	}
}

/// Gets the operand type
pub(crate) fn get_op_type(insn_ptr: *mut cs_insn, idx: usize) -> OpType {
	unsafe {
		(*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].type_
	}
}

// pub(crate) fn get_sys_op(insn_ptr: *mut cs_insn, idx: usize) -> SysReg {
// 	unsafe {
// 		(*(*insn_ptr).detail).__bindgen_anon_1.arm64.operands[idx].__bindgen_anon_1.reg
// 	}
// }

/// Gets the number of operand of an insn
pub(crate) fn get_op_cnt(insn_ptr: *mut cs_insn) -> u8 {
	unsafe {
		(*(*insn_ptr).detail).__bindgen_anon_1.arm64.op_count
	}
}

/// Gets the global capstone handle
/// 
/// # SAFETY
/// 
/// A getter of `GLOBAL_CSH`, read_only. 
/// Can only be used after `cs_rust::open()`
#[inline]
fn handle() -> csh {
	unsafe {
		**GLOBAL_CSH.as_ptr()
	}
}

/// Initializes the Capstone library
pub(crate) fn up() {
	if unsafe { kjit_cs_setup() } {
		let cs_handle = Arc::new(usize::default(), GFP_ATOMIC).unwrap();
		let csh_ptr = Arc::into_raw(cs_handle) as *mut csh;
		if let Err(err) = open(csh_ptr) {
		    pr_err!("Capstone handle acquisition failed, errno: {}\n", err);
		}
		GLOBAL_CSH.store(csh_ptr, Ordering::SeqCst);
	} else {
		pr_err!("Capstone init failed\n");
	}
}

/// Shuts down the Capstone library
pub(crate) fn down() {
	let csh_ptr = GLOBAL_CSH.swap(core::ptr::null_mut(), Ordering::SeqCst);
	if let Err(_) = close(csh_ptr) {
		pr_err!("Capstone close failed\n");
	}
	unsafe { Arc::from_raw(csh_ptr); }
}
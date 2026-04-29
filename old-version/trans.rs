//! `Trans` module aims to provide a translation toolkit for porting userspace code into kernelspace.
//!
//! # Goal
//! 
//! A super simple interface, which takes a starting address in userspace and output an `XPage` and a starting offset that can be saved and executed dirtectly
//! 
//! # How? 
//! 
//! - Iteratively disassembles the userspace memory 
//! - Performs control flow analysis with the disassembled result
//! - Translates the userspace instructions into kernel executable instructions, including modifications to B, RET, SVC, etc.
//! 
//! # Future Improvements
//! 
//! PAuth, MTE ...
//! 
//! # Return convention for RustUCA
//! 
//! Return value is stored in x0, just as in ARM64 ABI.
//! The return value is `ret_status`, which is used to distinguish return source (from SVC or BL, etc.)
//! 2 extra parameters are stored in Vec `extra_params`, the first is some immediate number,
//! the second is the address of the insn 'B to EPILOGUE'.

use kernel::prelude::*;
use kernel::pr_cont;
use kernel::task::pt_regs;
use alloc::fmt::{Debug, Formatter};
use crate::utils;
use crate::utils::multi_map::prelude::*;
use crate::utils::circ_buf::prelude::*;

const TRANS_DEBUG: bool = false;
const PRINT_BASIC_BLOCKS: bool = true;
const PRINT_VLABELS: bool = false;
const PRINT_FINAL_CODE: bool = true;

pub(crate) mod cs_rust;
pub(crate) use cs_rust::prelude::*;

pub(crate) mod prelude {
	pub(crate) use super::RetStatus;
	pub(crate) use super::Translator;
	#[macro_use]
	pub(crate) use super::assem;
	pub(crate) use super::assem::prelude::*;
	pub(crate) use super::{PROLOGUE_LEN, PROLOGUE_END, EPILOGUE_LEN};
}

/// All possible return status to the runtime
/// which is the return value of the executed code.
#[derive(Debug)]
pub(crate) enum RetStatus {
    RSvc   = 0,  // From SVC
    RBl    = 1,  // From BL
    RBlr   = 2,  // From BLR
    RBr    = 3,  // From BR
    RRet   = 4,  // From RET
    RMem   = 5,  // From MEM
    RDebug = 8,  // From DEBUG
    RInv,        // Invalid
}

impl From<u64> for RetStatus {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::RSvc,
            1 => Self::RBl,
            2 => Self::RBlr,
            3 => Self::RBr,
            4 => Self::RRet,
            5 => Self::RMem,
            8 => Self::RDebug,
            _ => Self::RInv,
        }
    }
}

#[macro_use]
pub(crate) mod assem;
mod conf_res;
pub(crate) use assem::prelude::*;
use conf_res::*;

// The following variables can be uncommented to optimize performance
// The corresponding assembly code is in Translator::code_gen()
// static PROLOGUE: [u8; 132] = [0xFD, 0x7B, 0xB5, 0xA9, 0xF2, 0x27, 0x00, 0xF9, 
// 							0xF3, 0x53, 0x05, 0xA9, 0xF5, 0x5B, 0x06, 0xA9, 
// 							0xF7, 0x63, 0x07, 0xA9, 0xF9, 0x6B, 0x08, 0xA9, 
// 							0xFB, 0x73, 0x09, 0xA9, 0xF0, 0x03, 0x00, 0xAA, 
// 							0xF1, 0x03, 0x01, 0xAA, 0xF0, 0x47, 0x0A, 0xA9, 
// 							0x00, 0x06, 0x40, 0xA9, 0x02, 0x0E, 0x41, 0xA9, 
// 							0x04, 0x16, 0x42, 0xA9, 0x06, 0x1E, 0x43, 0xA9, 
// 							0x08, 0x26, 0x44, 0xA9, 0x0A, 0x2E, 0x45, 0xA9, 
// 							0x0C, 0x36, 0x46, 0xA9, 0x0E, 0x3E, 0x47, 0xA9, 
// 							0x12, 0x4E, 0x49, 0xA9, 0x14, 0x56, 0x4A, 0xA9, 
// 							0x16, 0x5E, 0x4B, 0xA9, 0x18, 0x66, 0x4C, 0xA9, 
// 							0x1A, 0x6E, 0x4D, 0xA9, 0x1C, 0x76, 0x4E, 0xA9, 
// 							0x1E, 0x7A, 0x40, 0xF9, 0x11, 0x7E, 0x40, 0xF9, 
// 							0xF1, 0x23, 0x00, 0xF9, 0x10, 0x46, 0x48, 0xA9, 
// 							0xEC, 0x37, 0x01, 0xA9, 0xEE, 0x3F, 0x02, 0xA9, 
// 							0xF0, 0x47, 0x03, 0xA9, 0xF1, 0x23, 0x40, 0xF9, 
// 							0x1F, 0x20, 0x03, 0xD5];

// static EPILOGUE: [u8; 128] = [0xF1, 0x23, 0x00, 0xF9, 0xF0, 0x47, 0x4A, 0xA9, 
// 							  0x2A, 0x2E, 0x00, 0xA9, 0xEE, 0x3F, 0x41, 0xA9, 
// 							  0x0E, 0x3E, 0x06, 0xA9, 0xEE, 0x3F, 0x42, 0xA9, 
// 							  0x0E, 0x3E, 0x07, 0xA9, 0xEE, 0x3F, 0x43, 0xA9, 
// 							  0x0E, 0x3E, 0x08, 0xA9, 0xEE, 0x23, 0x40, 0xF9, 
// 							  0x0E, 0x7E, 0x00, 0xF9, 0x00, 0x06, 0x00, 0xA9, 
// 							  0x02, 0x0E, 0x01, 0xA9, 0x04, 0x16, 0x02, 0xA9, 
// 							  0x06, 0x1E, 0x03, 0xA9, 0x08, 0x22, 0x00, 0xF9, 
// 							  0x12, 0x4E, 0x09, 0xA9, 0x14, 0x56, 0x0A, 0xA9, 
// 							  0x16, 0x5E, 0x0B, 0xA9, 0x18, 0x66, 0x0C, 0xA9, 
// 							  0x1A, 0x6E, 0x0D, 0xA9, 0x1C, 0x76, 0x0E, 0xA9, 
// 							  0x1E, 0x7A, 0x00, 0xF9, 0xE0, 0x03, 0x09, 0xAA, 
// 							  0xF2, 0x27, 0x40, 0xF9, 0xF3, 0x53, 0x45, 0xA9, 
// 							  0xF5, 0x5B, 0x46, 0xA9, 0xF7, 0x63, 0x47, 0xA9, 
// 							  0xF9, 0x6B, 0x48, 0xA9, 0xFB, 0x73, 0x49, 0xA9, 
// 							  0xFD, 0x7B, 0xCB, 0xA8, 0xC0, 0x03, 0x5F, 0xD6];

static NOP_BYTES: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];

pub(crate) const PROLOGUE_LEN: usize = 0x90;
pub(crate) const PROLOGUE_END: usize = PROLOGUE_LEN - 0x4;
pub(crate) const EPILOGUE_LEN: usize = 0x88;

/// A struct to represent one basic block in cfg, `insns` field contains pointers to `cs_insn` and will be FREED when dropped.
#[derive(Default)]
struct BasicBlock {
	starting_addr: u64,
	ending_addr: u64,  // We have to keep tract of this to jump back to userspace
	insns: Vec<*mut cs_insn>,
	bytes: Vec<u8>, 	// a list of bytes corresponding to insns
	// For list of prev and next, starting addr is used for versatility.
	prev: Vec<u64>,  // a list of previous bb(s), referring to them with their starting addr
	next: Vec<u64>, 	// a list of following bb(s), referring to them with their starting addr
	occupied_regs: u64,  // 0-30 bits are used for Xn, 31 for XZR, 32 for SP
}

impl Debug for BasicBlock {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
		write!(f, "\n*** BasicBlock starts {:#x?} ***\n", self.starting_addr)?;

		for i in 0..self.prev.len() {
			write!(f, "{:#x?} ->\n", self.prev[i])?;
		}

		for i in 0..self.insns.len() {
			let insn_ptr: *mut cs_insn = self.insns[i];
			write!(f, "\t{:?}\n", Insn::from(unsafe { (*insn_ptr).id }))?;
		}

		write!(f, "Bytes: ")?;
		for i in 0..self.bytes.len() {
			write!(f, "{:02x} ", self.bytes[i])?;
		}

		for i in 0..self.next.len() {
			write!(f, "-> {:#x?}\n", self.next[i])?;
		}

		write!(f, "****** BasicBlock ends {:#x?} ******\n", self.ending_addr)?;
		Ok(())
	}
}

impl Drop for BasicBlock {
	fn drop(&mut self) {
	    free_insns(&self.insns);
	}
}

/// `Translator` is used to translate user space code into kernel space, enforcing necessary transformations and security scrutiny.
pub(crate) struct Translator {
	lift_entry_addr: u64,         // Entry address of the lift context
	lift_entry_offset: usize,     // Entry offset of the lift context
	trans_entry_addr: u64,        // Entry address of the current translation session
	trans_entry_offset: usize,    // Entry offset of the current translation session
	code_offset: usize,           // Current length of code generated
	vlabels: MultiMap<u64, usize>,  // virtual labels, mapping real address to offset in final code
	found_loop: bool, 		          // whether we have encountered a loop or not
	failed_addresses: Vec<u64>,
}

impl Translator {
	/// Creates a new `Translator`.
	pub(crate) fn new() -> Self {
		Self {
			lift_entry_addr: 0,
			lift_entry_offset: 0,
			trans_entry_addr: 0,
			trans_entry_offset: 0,
			code_offset: 0,
			vlabels: MultiMap::new(),
			found_loop: false,
			failed_addresses: Vec::new(),
		}
	}

	/// Outputs the translated machine code starting from `entry_addr`.
	pub(crate) fn trans(&mut self, entry_addr: u64) -> Result<Vec<u8>> {
		self.trans_entry_addr = entry_addr;
		if self.lift_entry_addr == 0 {
			// Set this value once only
			self.lift_entry_addr = self.trans_entry_addr;
		}

		// If we have failed to translate from this entry_addr before,
		// we just return Err to avoid redundant work.
		for i in 0..self.failed_addresses.len() {
			if self.failed_addresses[i] == entry_addr {
				return Err(ERANGE);
			}
		}

		if let Ok(ret) = self.__trans() {
			Ok(ret)
		} else {
			self.failed_addresses.push(entry_addr, GFP_ATOMIC).unwrap();
			Err(ERANGE)
		}
	}

	fn __trans(&mut self) -> Result<Vec<u8>> {
		let addr = self.trans_entry_addr;
		// We pass basic blocks around and they will be freed right after this method returns
		let mut basic_blocks = Vec::new();
		self.cfa(&mut basic_blocks)?;
		self.preprocess(&mut basic_blocks)?;
		Ok(self.code_gen(&mut basic_blocks)?)
	}

	/// Gets the real offset to the entry insn of the most recent translation session.
	pub(crate) fn get_trans_entry_offset(&self) -> usize {
		self.trans_entry_offset
	}

	/// Gets the real offset to the entry insn of the lift context associated with this Translator.
	pub(crate) fn get_lift_entry_offset(&self) -> usize {
		self.lift_entry_offset
	}

	/// Gets a reference to virtual labels.
	pub(crate) fn get_vlabels(&self) -> &MultiMap<u64, usize> {
		&self.vlabels
	}

	/// Checks if we have found the loop in this lift context
	pub(crate) fn found_loop(&self) -> bool {
		self.found_loop
	}

	/// Control Flow Analysis
	fn cfa(&mut self, basic_blocks: &mut Vec<BasicBlock>) -> Result<()> {
		let buffer_size = 64;
		// A circular buffer of starting addresses waiting to be analyzed
		let mut addr_q: CircBuf<u64> = CircBuf::with_capacity(buffer_size, GFP_ATOMIC).unwrap();
		addr_q.enque(self.trans_entry_addr).unwrap();

		let mut first = true;

		'cfa:
		while !addr_q.is_empty() {
			let starting_addr = addr_q.deque().unwrap();

			// If we can find this basic block's starting_addr in vlabels,
			// it means we have explored this in some previous translation session. So we simply continues to the next round
			if self.vlabels.find(starting_addr).is_some() {
				continue 'cfa;
			}

			// Then we go through every basic block and check if the current starting address is within an already-analyzed one.
			// Note: If we branch into the middle of some basic block, let's makes this basic block into 2 separate ones.
			for i in 0..basic_blocks.len() {
				let curr_bb: &mut BasicBlock = &mut basic_blocks[i];
				if curr_bb.starting_addr == starting_addr {
					// We've explored this basic block.
					continue 'cfa;
				} else if curr_bb.starting_addr < starting_addr 
											   && starting_addr < curr_bb.starting_addr + curr_bb.bytes.len() as u64
				{
					// Current starting address is a B target, spliting this basic block into 2 separate ones: 
					// [-- curr_bb --] + [-- b_target + rest of new_bb --] 
					let bytes_offset = (starting_addr - curr_bb.starting_addr) as usize;
					let nr_insns = bytes_offset / 4;
					let new_starting_addr = starting_addr;
					let new_ending_addr = curr_bb.ending_addr;
					curr_bb.ending_addr = starting_addr - 4;

					// Move the following insns to new_bb, we have to keep the sequence thus we can't use `pop()` directly
					let mut new_bb_insns = Vec::new();
					let insns_len = curr_bb.insns.len();
					for ii in nr_insns..insns_len {
						new_bb_insns.push(curr_bb.insns[ii], GFP_ATOMIC).unwrap();
					}
					for ii in nr_insns..insns_len {
						curr_bb.insns.pop().unwrap();
					}

					// Move the following bytes to new_bb
					let mut new_bb_bytes = Vec::new();
					let bytes_len = curr_bb.bytes.len();
					for ii in bytes_offset..bytes_len {
						new_bb_bytes.push(curr_bb.bytes[ii], GFP_ATOMIC).unwrap();
					}
					for ii in bytes_offset..bytes_len {
						curr_bb.bytes.pop().unwrap();
					}

					// Update the `next` vector
					let mut new_bb_next = Vec::new();
					new_bb_next.push(starting_addr, GFP_ATOMIC);
					core::mem::swap(&mut new_bb_next, &mut curr_bb.next);

					basic_blocks.push(
						BasicBlock {
							starting_addr: new_starting_addr,
							ending_addr: new_ending_addr,
							insns: new_bb_insns,
							bytes: new_bb_bytes,
							prev: Vec::new(),
							next: new_bb_next,
							occupied_regs: 0,
						}
						, GFP_ATOMIC
					).unwrap();

					// Now we are good to go!
					continue 'cfa;
				}
			}

			let mut addr = starting_addr;
			let mut insns = Vec::new();
			let mut bytes = Vec::new();
			let mut next = Vec::new();

			'disasm:
			while let Ok(mem) = utils::read_mem(addr, 4) {
				// If the current address is the starting address of another block, 
				// it means we have explored the following code, break now.
				// NOTE: Current addr is probably b_target of some previous insn.
				for i in 0..basic_blocks.len() {
					if addr == basic_blocks[i].starting_addr {
						next.push(addr, GFP_ATOMIC).unwrap();
						break 'disasm;
					}
				}

				let mut code = mem.as_ptr();
				let mut size = mem.len();

				utils::append(&mut bytes, &mem).unwrap();

				// `addr += 4` is done automatically by `disasm_iter()`
				if let Ok(insn_ptr) = disasm_iter(
										&mut code as *mut *const u8,
										&mut size as *mut usize,
										&mut addr as *mut u64
				) {
					insns.push(insn_ptr, GFP_ATOMIC)?;
					// ! TEST
					// analyze_insn(insn_ptr);
					
					match unsafe { Insn::from((*insn_ptr).id) } {
						Insn::ARM64_INS_INVALID => {
							pr_err!("Invalid Instruction\n");
							return Err(EFAULT);
						}
						Insn::ARM64_INS_B => {
							// Unconditional/Conditional Branch
							if let Op::IMM(b_target) = get_operand(insn_ptr, 0) {
								let b_target = b_target as u64;
								match Cond::from(get_cc(insn_ptr)) {
									Cond::AL | Cond::NV => {
										// Only one execution path
										next.push(b_target, GFP_ATOMIC).unwrap();
										addr_q.enque(b_target).unwrap();
									}
									_ => {
										// Two possible execution paths: B or not
										next.push(b_target, GFP_ATOMIC).unwrap();
										next.push(addr, GFP_ATOMIC).unwrap();
										addr_q.enque(b_target).unwrap();
										addr_q.enque(addr).unwrap();
									}
								}
								break;
							} else {
								pr_err!("Wrong B operand\n");
								return Err(EFAULT);
							}
						}
						Insn::ARM64_INS_BL => {
							// Static subroutine call
							if let Op::IMM(b_target) = get_operand(insn_ptr, 0){
								let b_target = b_target as u64;
								next.push(b_target, GFP_ATOMIC).unwrap();
								addr_q.enque(addr).unwrap();
								break;
							} else {
								pr_err!("Wrong BL operand\n");
								return Err(EFAULT);
							}
						}
						Insn::ARM64_INS_BLR => {
							// Dynamic subroutine call
							if let Op::REG(_) = get_operand(insn_ptr, 0){
								next.push(addr, GFP_ATOMIC).unwrap();
								break;
							} else {
								pr_err!("Wrong BLR operand\n");
								return Err(EFAULT);
							}
						}
						Insn::ARM64_INS_BR => {
							// Dynamic branch, we are not going back,
							// thus we do NOT explore the following address
							if let Op::REG(_) = get_operand(insn_ptr, 0){
								break;
							} else {
								pr_err!("Wrong BR operand\n");
								return Err(EFAULT);
							}
						}
						Insn::ARM64_INS_CBNZ |
						Insn::ARM64_INS_CBZ  => {
							// Compare and Branch
							if let Op::IMM(b_target) = get_operand(insn_ptr, 1){
								let b_target = b_target as u64;
								// To B or not to B
								next.push(b_target, GFP_ATOMIC).unwrap();
								next.push(addr, GFP_ATOMIC).unwrap();
								addr_q.push(b_target).unwrap();
								addr_q.push(addr).unwrap();
								break;
							} else {
								pr_err!("Wrong CBNZ/CBZ operand\n");
								return Err(EFAULT);
							}
						}
						Insn::ARM64_INS_RET => {
							// Returning from subroutine
							break;
						}
						Insn::ARM64_INS_SVC => {
							// SVC is just like a function call
							next.push(addr, GFP_ATOMIC).unwrap();
							addr_q.push(addr).unwrap();
							break;
						}
						Insn::ARM64_INS_TBNZ |
						Insn::ARM64_INS_TBZ  => {
							// Test bit and Branch
							if let Op::IMM(b_target) = get_operand(insn_ptr, 2){
								let b_target = b_target as u64;
								next.push(b_target, GFP_ATOMIC).unwrap();
								next.push(addr, GFP_ATOMIC).unwrap();
								addr_q.push(b_target).unwrap();
								addr_q.push(addr).unwrap();
								break;
							} else {
								pr_err!("Wrong TBNZ/TBZ operand\n");
								return Err(EFAULT);
							}
						}
						_ => {
							// Other instructions, passing through
						}
					}
				} else {
					pr_err!("disasm_iter() failed for {:?}\n", mem);
					return Err(EFAULT);
				}
			}

			if insns.is_empty() {
				// We failed to disassemble anything.
				pr_err!("No instructions disassembled\n");
				return Err(EFAULT);
			}

			// On loop exit, addr == real_ending_addr + 4
			let ending_addr = addr - 4;

			// SVC loop detection. By comparing the current address with `lift_entry_addr - 4`
			// We ensure that we find the way back to the entering SVC instruction
			if ending_addr == self.lift_entry_addr - 4 {
				// ! TEST
				pr_info!("Loop detected\n");
				self.found_loop = true;
			}

			basic_blocks.push(
				BasicBlock {
					starting_addr,
					ending_addr,
					insns,
					bytes,
					prev: Vec::new(),
					next,
					occupied_regs: 0,
				}
				, GFP_ATOMIC
			).unwrap();
		}

		// Sorts all basic blocks before proceeding for further analysis
		sort_basic_blocks(basic_blocks);

		// Do another traversal to set the `prev` field, O(n^2)
		// for i in 0..basic_blocks.len() {
		// 	let curr_bb: &BasicBlock = &basic_blocks[i];
		// 	// For every next basic block
		// 	for ii in 0..curr_bb.next.len() {
		// 		let n: u64 = curr_bb.next[ii];
		// 		// Find that basic block and update its `prev`
		// 		for iii in 0..basic_blocks.len() {
		// 			// Fancy cast to satisfy our compiler
		// 			let possible_next: *mut BasicBlock = &basic_blocks[iii] as *const _ as *mut BasicBlock;
		// 			// Safety: possible_next might be any element in our basic blocks, and it's guaranteed to be non-null
		// 			// as it is accessed with index `iii` and we won't modify the length of `basic_blocks` in the unsafe code.
		// 			unsafe {
		// 				if (*possible_next).starting_addr == n {
		// 					(*possible_next).prev.push(curr_bb.starting_addr, GFP_ATOMIC).unwrap();
		// 					break;
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		// ! DEBUG
		if PRINT_BASIC_BLOCKS {
			for i in 0..basic_blocks.len() {
				let curr_bb: &BasicBlock = &basic_blocks[i];
				pr_info!("BB at {:#x}\n", curr_bb.starting_addr);
				utils::print_bytes(curr_bb.bytes.as_ptr(), curr_bb.bytes.len(), "BB");
			}
		}
		
		Ok(())
	}

	/// Preprocesses the code block, get ready for code generation
	/// 
	/// All basic blocks contain valid instruction pointers in `insns` on exit and will be freed when `Translator` is dropped.
	/// Other instructions that got translated are freed in this method.
	fn preprocess(&mut self, basic_blocks: &mut Vec<BasicBlock>) -> Result<()> {
		let mut insns_pending_free = Vec::new();
		for i in 0..basic_blocks.len() {
			// One resolver for every basic block
			let mut conf_res = ConfResolver::new();
			let curr_bb: &mut BasicBlock = &mut basic_blocks[i];
			
			let mut tmp_insns = Vec::new();
			let mut tmp_bytes = Vec::new();

			// Implementation details:
			// 1. We preprocess/translate all special instructions here: 
			// x9 will contain the return status and x10, x11 will contain extra params
			for ii in 0..curr_bb.insns.len() {
				let insn_ptr: *mut cs_insn = curr_bb.insns[ii];
                let curr_addr = unsafe { (*insn_ptr).address };
				// If this instruction is translated, we will free it after translation. Otherwise we can NOT free it.
				let insn_type = unsafe { Insn::from((*insn_ptr).id) };
				match insn_type {
					Insn::ARM64_INS_ADR  |
					Insn::ARM64_INS_ADRP => {
						// PC is different during lifting, we have to directly load the ADR/ADRP result into target reg
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							if let Op::IMM(i) = get_operand(insn_ptr, 1) {
								// Capstone outputs the final value directly
								let mut replace_bytes = assem![
									; MOVZ_RIF 		(r, ((i >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
									; MOVK_RIF 		(r, ((i >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
									; MOVK_RIF 		(r, ((i >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
									; MOVK_RIF 		(r, ((i >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
								];
								utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
								utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
							} else {
								pr_err!("Incorrect ADR(P) operand\n");
								return Err(EFAULT);
							}
						} else {
							pr_err!("Incorrect ADR(P) operand\n");
							return Err(EFAULT);
						}
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					Insn::ARM64_INS_B => {
						if TRANS_DEBUG {
							if let Op::IMM(i) = get_operand(insn_ptr, 0) {
								let cc = get_cc(insn_ptr);
								let mut replace_bytes = assem![
									; MRS_RS 		(Reg::X(9), SysReg::NZCV)
									; MOVK_RIF 		(Reg::X(9), RetStatus::RDebug as u32, (ShiftCls::LSL, 0))
									; MOVK_RIF 		(Reg::X(9), cc, (ShiftCls::LSL, 32))
									; MOVZ_RIF 		(Reg::X(10), ((i >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
									; MOVK_RIF 		(Reg::X(10), ((i >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
									; MOVK_RIF 		(Reg::X(10), ((i >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
									; MOVK_RIF 		(Reg::X(10), ((i >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
									; ADR_RI 		(Reg::X(11), 4)
									; B_I 			(0)
								];
								utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
								utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
							} else {
								pr_err!("Incorrect B operand\n");
								return Err(EFAULT);
							}
							insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
						} else {
							tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
							utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
						}
					}
					Insn::ARM64_INS_BL => {
						if let Op::IMM(i) = get_operand(insn_ptr, 0) {
							let mut replace_bytes = assem![
								; MOV_RI 		(Reg::X(9), RetStatus::RBl as u32)
								; MOVZ_RIF 		(Reg::X(10), ((i >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
								; MOVK_RIF 		(Reg::X(10), ((i >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
								; MOVK_RIF 		(Reg::X(10), ((i >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
								; MOVK_RIF 		(Reg::X(10), ((i >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
								; ADR_RI 		(Reg::X(11), 4)
								; B_I 			(0)
							];
							utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
							utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
						} else {
							pr_err!("Incorrect BL operand\n");
							return Err(EFAULT);
						}
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					Insn::ARM64_INS_BLR => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							let mut replace_bytes = assem![
								; MOV_RI 		(Reg::X(9), RetStatus::RBlr as u32)
								// We simply move the BLR target value into X10 so we can treat this the same as BL
								; MOV_RR 		(Reg::X(10), r)
								; ADR_RI 		(Reg::X(11), 4)
								; B_I 			(0)
							];
							utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
							utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
						} else {
							pr_err!("Incorrect BLR operand\n");
							return Err(EFAULT);
						}
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					Insn::ARM64_INS_BR => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							let mut replace_bytes = assem![
								; MOV_RI 		(Reg::X(9), RetStatus::RBr as u32)
								// We simply move the BLR target value into X10 so we can treat this the same as BL
								; MOV_RR 		(Reg::X(10), r)
								; ADR_RI 		(Reg::X(11), 4)
								; B_I 			(0)
							];
							utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
							utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
						} else {
							pr_err!("Incorrect BR operand\n");
							return Err(EFAULT);
						}
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					// Insn::ARM64_INS_CBNZ => {
					// 	if TRANS_DEBUG {
					// 		if let Op::REG(r) = get_operand(insn_ptr, 0) {
					// 			let r = Reg::from(r);
					// 			if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
					// 				let mut replace_bytes = assem![
					// 					; CMP_RI 		(r, 0)
					// 					; MRS_RS 		(Reg::X(9), SysReg::NZCV)
					// 					; MOVK_RIF 		(Reg::X(9), RetStatus::RDebug as u32, (ShiftCls::LSL, 0))
					// 					// Be aware of `+ 1` for Cond to map correctly
					// 					; MOVK_RIF 		(Reg::X(9), Cond::NE as u32 + 1, (ShiftCls::LSL, 32))
					// 					; MOVZ_RIF 		(Reg::X(10), ((i0 >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
					// 					; ADR_RI 		(Reg::X(11), 4)
					// 					; B_I 			(0)
					// 				];
					// 				utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
					// 				utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
					// 			} else {
					// 				pr_err!("Incorrect CBNZ operand\n");
					// 				return Err(EFAULT);
					// 			}
					// 		} else {
					// 			pr_err!("Incorrect CBNZ operand\n");
					// 			return Err(EFAULT);
					// 		}
					// 		insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 	} else {
					// 		tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 		utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
					// 	}
					// }
					// Insn::ARM64_INS_CBZ => {
					// 	if TRANS_DEBUG {
					// 		if let Op::REG(r) = get_operand(insn_ptr, 0) {
					// 			let r = Reg::from(r);
					// 			if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
					// 				let mut replace_bytes = assem![
					// 					; CMP_RI 		(r, 0)
					// 					; MRS_RS 		(Reg::X(9), SysReg::NZCV)
					// 					; MOVK_RIF 		(Reg::X(9), RetStatus::RDebug as u32, (ShiftCls::LSL, 0))
					// 					; MOVK_RIF 		(Reg::X(9), Cond::EQ as u32 + 1, (ShiftCls::LSL, 32))
					// 					; MOVZ_RIF 		(Reg::X(10), ((i0 >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
					// 					; MOVK_RIF 		(Reg::X(10), ((i0 >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
					// 					; ADR_RI 		(Reg::X(11), 4)
					// 					; B_I 			(0)
					// 				];
					// 				utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
					// 				utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
					// 			} else {
					// 				pr_err!("Incorrect CBZ operand\n");
					// 				return Err(EFAULT);
					// 			}
					// 		} else {
					// 			pr_err!("Incorrect CBZ operand\n");
					// 			return Err(EFAULT);
					// 		}
					// 		insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 	} else {
					// 		tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 		utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
					// 	}
					// }
					Insn::ARM64_INS_RET => {
						let mut replace_bytes = assem![
							; MOV_RI 		(Reg::X(9), RetStatus::RRet as u32)
							// Move the return to address into X10 and treat this the same as a BL/BLR except that this does not update X30
							// After we do JIT and resume execution, X0 (return value) will be loaded automatically
							; MOV_RR 		(Reg::X(10), Reg::X(30))
							; ADR_RI 		(Reg::X(11), 4)
							; B_I 			(0)
						];
						utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
						utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					Insn::ARM64_INS_SVC => {
						let mut replace_bytes = assem![
							; MOV_RI 		(Reg::X(9), RetStatus::RSvc as u32)
							// Syscallno is moved into x10
							; MOV_RR 		(Reg::X(10), Reg::X(8))
							; ADR_RI 		(Reg::X(11), 4)
							; B_I 			(0)
						];
						utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
						utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					// Insn::ARM64_INS_TBNZ => {
					// 	if TRANS_DEBUG {
					// 		if let Op::REG(r) = get_operand(insn_ptr, 0) {
					// 			let r = Reg::from(r);
					// 			if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
					// 				if let Op::IMM(i1) = get_operand(insn_ptr, 2) {
					// 					let mut replace_bytes = assem![
					// 						; MOV_RI 		(Reg::X(9), 1)
					// 						; ANDS_RRRF 	(Reg::X(31), r, Reg::X(9), (ShiftCls::LSL, i0 as u8))
					// 						; MRS_RS 		(Reg::X(9), SysReg::NZCV)
					// 						; MOVK_RIF 		(Reg::X(9), RetStatus::RDebug as u32, (ShiftCls::LSL, 0))
					// 						// Be aware of `+ 1` for Cond to map correctly
					// 						; MOVK_RIF 		(Reg::X(9), Cond::NE as u32 + 1, (ShiftCls::LSL, 32))
					// 						; MOVZ_RIF 		(Reg::X(10), ((i1 >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
					// 						; ADR_RI 		(Reg::X(11), 4)
					// 						; B_I 			(0)
					// 					];
					// 					utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
					// 					utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
					// 				} else {
					// 					pr_err!("Incorrect TBNZ operand\n");
					// 					return Err(EFAULT);
					// 				}
					// 			} else {
					// 				pr_err!("Incorrect TBNZ operand\n");
					// 				return Err(EFAULT);
					// 			}
					// 		} else {
					// 			pr_err!("Incorrect TBNZ operand\n");
					// 			return Err(EFAULT);
					// 		}
					// 		insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 	} else {
					// 		tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 		utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
					// 	}
					// }
					// Insn::ARM64_INS_TBZ => {
					// 	if TRANS_DEBUG {
					// 		if let Op::REG(r) = get_operand(insn_ptr, 0) {
					// 			let r = Reg::from(r);
					// 			if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
					// 				if let Op::IMM(i1) = get_operand(insn_ptr, 2) {
					// 					let mut replace_bytes = assem![
					// 						; MOV_RI 		(Reg::X(9), 1)
					// 						; ANDS_RRRF 	(Reg::X(31), r, Reg::X(9), (ShiftCls::LSL, i0 as u8))
					// 						; MRS_RS 		(Reg::X(9), SysReg::NZCV)
					// 						; MOVK_RIF 		(Reg::X(9), RetStatus::RDebug as u32, (ShiftCls::LSL, 0))
					// 						// Be aware of `+ 1` for Cond to map correctly
					// 						; MOVK_RIF 		(Reg::X(9), Cond::EQ as u32 + 1, (ShiftCls::LSL, 32))
					// 						; MOVZ_RIF 		(Reg::X(10), ((i1 >> 48) & 0xFFFF) as u32, (ShiftCls::LSL, 48))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 32) & 0xFFFF) as u32, (ShiftCls::LSL, 32))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 16) & 0xFFFF) as u32, (ShiftCls::LSL, 16))
					// 						; MOVK_RIF 		(Reg::X(10), ((i1 >> 0 ) & 0xFFFF) as u32, (ShiftCls::LSL, 0 ))
					// 						; ADR_RI 		(Reg::X(11), 4)
					// 						; B_I 			(0)
					// 					];
					// 					utils::append(&mut tmp_bytes, &replace_bytes).unwrap();
					// 					utils::append(&mut tmp_insns, &disasm_preserve_first_addr(replace_bytes.as_ptr(), replace_bytes.len(), curr_addr).unwrap());
					// 				} else {
					// 					pr_err!("Incorrect TBZ operand 2\n");
					// 					return Err(EFAULT);
					// 				}
					// 			} else {
					// 				pr_err!("Incorrect TBZ operand 1\n");
					// 				return Err(EFAULT);
					// 			}
					// 		} else {
					// 			pr_err!("Incorrect TBZ operand 0\n");
					// 			return Err(EFAULT);
					// 		}
					// 		insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 	} else {
					// 		tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
					// 		utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
					// 	}
					// }
					// All following instructions are translated to NOP for the moment
					// And we preserve the address so that this line can still be added to vlabels
					Insn::ARM64_INS_BTI     |
					Insn::ARM64_INS_PACIAZ  |
					Insn::ARM64_INS_PACIASP |
					Insn::ARM64_INS_PACIBZ  |
					Insn::ARM64_INS_PACIBSP |
					Insn::ARM64_INS_AUTIAZ  |
					Insn::ARM64_INS_AUTIASP |
					Insn::ARM64_INS_AUTIBZ  |
					Insn::ARM64_INS_AUTIBSP => {
						// ! TEST
						pr_info!("{:?} -> NOP\n", insn_type);
						utils::append(&mut tmp_bytes, &NOP_BYTES).unwrap();
						tmp_insns.push(disasm_one_preserve_addr(NOP_BYTES.as_ptr(), curr_addr).unwrap(), GFP_ATOMIC).unwrap();
						insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
					}
					_ => {
						tmp_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
						utils::append(&mut tmp_bytes, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)]).unwrap();
					}
				}
			}

			// This prevents Double Free of previously freed insns when `ConfResolver::resolve()` failed.
			curr_bb.insns = tmp_insns;
			curr_bb.bytes = tmp_bytes;
			// ! PENDING
			// free_insns(&insns_pending_free);

			// 2. Pass all instructions inside this basic block to `conf_res` to generate the preprocessed code for this block
			let mut preproc_insns = Vec::new();
			let mut preproc_bytes = Vec::new();
			
			for ii in 0..curr_bb.insns.len() {
				let insn_ptr: *mut cs_insn = curr_bb.insns[ii];
				// ConfResolver::resolve()` will free extraneous insns on success and keep them unfreed if failed.
				let (resolved_insns, resolved_bytes) = conf_res.resolve(insn_ptr, &curr_bb.bytes[(ii * 4)..((ii + 1) * 4)])?;
				utils::append(&mut preproc_insns, &resolved_insns).unwrap();
				utils::append(&mut preproc_bytes, &resolved_bytes).unwrap();
			}

			// Recover all used special regs at the end of each basic block
			conf_res.recover(&mut preproc_insns, &mut preproc_bytes);

			curr_bb.insns = preproc_insns;
			curr_bb.bytes = preproc_bytes;
		}

		Ok(())
	}

	fn decode_branch(&self, code: &mut Vec<u8>, insn_ptr: *mut cs_insn, offset: i32, idx: usize) -> Result<()> {
		match unsafe { Insn::from((*insn_ptr).id) } {
			Insn::ARM64_INS_B => {
				let tmp = 
					match Cond::from(get_cc(insn_ptr)) {
						Cond::AL | Cond::NV => {
							assem![
								; B_I 		(offset as u32)
							]
						}
						cc => {
							assem![
								; BC_IC 	(offset as u32, cc)
							]
						}
					};
				utils::replace_insn(code, &tmp, idx).unwrap();
			}
			Insn::ARM64_INS_CBNZ => {
				if let Op::REG(r) = get_operand(insn_ptr, 0) {
					let tmp = assem![
						; CBNZ_RI 		(Reg::from(r), offset as u32)
					];
					utils::replace_insn(code, &tmp, idx).unwrap();
				} else {
					pr_err!("Wrong CBNZ operand\n");
					return Err(EFAULT);
				}
			}
			Insn::ARM64_INS_CBZ => {
				if let Op::REG(r) = get_operand(insn_ptr, 0) {
					let tmp = assem![
						; CBZ_RI 		(Reg::from(r), offset as u32)
					];
					utils::replace_insn(code, &tmp, idx).unwrap();
				} else {
					pr_err!("Wrong CBZ operand\n");
					return Err(EFAULT);
				}
			}
			Insn::ARM64_INS_TBNZ => {
				if let Op::REG(r) = get_operand(insn_ptr, 0) {
					if let Op::IMM(test_bit) = get_operand(insn_ptr, 1) {
						let tmp = assem![
							; TBNZ_RII 		(Reg::from(r), test_bit as u32, offset as u32)
						];
						utils::replace_insn(code, &tmp, idx).unwrap();
					} else {
						pr_err!("Wrong TBNZ operand 1\n");
						return Err(EFAULT);
					}
				} else {
					pr_err!("Wrong TBNZ operand 0\n");
					return Err(EFAULT);
				}
			}
			Insn::ARM64_INS_TBZ => {
				if let Op::REG(r) = get_operand(insn_ptr, 0) {
					if let Op::IMM(test_bit) = get_operand(insn_ptr, 1) {
						let tmp = assem![
							; TBZ_RII 		(Reg::from(r), test_bit as u32, offset as u32)
						];
						utils::replace_insn(code, &tmp, idx).unwrap();
					} else {
						pr_err!("Wrong TBZ operand 1\n");
						return Err(EFAULT);
					}
				} else {
					pr_err!("Wrong TBZ operand 0\n");
					return Err(EFAULT);
				}
			}
			_ => {
				pr_err!("Wrong insn to resolve\n");
				return Err(ERANGE);
			}
		}
		Ok(())
	}

	/// Resolves branching instructions in `code`
	/// 
	/// Now supports all static branch instructions (except subroutine calls): B, CBNZ, CBZ, TBNZ, TBZ
	fn resolve_branch(&self, code: &mut Vec<u8>, curr_addr: u64, pending_b_insns: &MultiMap<u64, (usize, *mut cs_insn)>) -> Result<()> {
		// We are branching from previous B insn to this basic block,
		// so `vlabels` is not useful and we only need relative offsets within `final_code` (`code_offset` is useless as well)
		let indices = pending_b_insns.find_all(curr_addr).unwrap();
		for i in 0..indices.len() {
			let (idx, insn_ptr) = indices[i];
			let offset = code.len() as i32 - idx as i32;

			if insn_ptr.is_null() {
				// This is the special case for PROLOGUE to B to entry addr
				// Could also be used to resolve other branch instructions as an unconditional branch
				let tmp = assem![
					; B_I 		(offset as u32)
				];
				utils::replace_insn(code, &tmp, idx).unwrap();
				continue;
			}

			self.decode_branch(code, insn_ptr, offset, idx)?;
		}
		Ok(())
	}

	/// This method generate the final code. 
	/// What this method does is essentially wrapping the code if required and resolve all branching instructions.
	/// Another key feature is that it will fill in `vlabels`, which is a field of `Translator`.
	fn code_gen(&mut self, basic_blocks: &mut Vec<BasicBlock>) -> Result<Vec<u8>> {
		// Branching insns to be resolved later, mapping label queries to the offset in final_code and its instruction pointer
		let mut pending_b_insns: MultiMap<u64, (usize, *mut cs_insn)> = MultiMap::new();
		let mut final_code: Vec<u8> = Vec::new();

		if self.vlabels.is_empty() {
			if self.code_offset != 0 {
				pr_err!("code_gen error: vlabels is empty but code_offset != 0\n");
				return Err(ERANGE);
			}
			// We have to follow the calling conventions of ARM64
			let prologue = assem![
				// Backup callee-saved regs
				; STP_RRM 		(Reg::X(29), Reg::X(30), (Reg::SP,    Reg::INV, (-16 * 12) as u32, MemAccCls::PreIndex))
				// Update frame pointer
				; MOV_RR 		(Reg::X(29), Reg::SP)
				; STR_RM 		(Reg::X(18),  			 (Reg::SP,    Reg::INV,  8 * 11, MemAccCls::Offset))
				; STP_RRM 		(Reg::X(19), Reg::X(20), (Reg::SP,    Reg::INV, 16 * 6,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(21), Reg::X(22), (Reg::SP,    Reg::INV, 16 * 7,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(23), Reg::X(24), (Reg::SP,    Reg::INV, 16 * 8,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(25), Reg::X(26), (Reg::SP,    Reg::INV, 16 * 9,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(27), Reg::X(28), (Reg::SP,    Reg::INV, 16 * 10, MemAccCls::Offset))
				// X0 is the first param: `*mut pt_regs`; X1 is the second param: a pointer to extra return params
				// We back them up here
				; MOV_RR 		(Reg::X(16), Reg::X(0))
				; MOV_RR 		(Reg::X(17), Reg::X(1))
				; STP_RRM 		(Reg::X(16), Reg::X(17), (Reg::SP,    Reg::INV, 16 * 11, MemAccCls::Offset))
				// Then we load the userspace environment
				; LDP_RRM 		(Reg::X(0),  Reg::X(1),  (Reg::X(16), Reg::INV, 16 * 0,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(2),  Reg::X(3),  (Reg::X(16), Reg::INV, 16 * 1,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(4),  Reg::X(5),  (Reg::X(16), Reg::INV, 16 * 2,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(6),  Reg::X(7),  (Reg::X(16), Reg::INV, 16 * 3,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(8),  Reg::X(9),  (Reg::X(16), Reg::INV, 16 * 4,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(10), Reg::X(11), (Reg::X(16), Reg::INV, 16 * 5,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(12), Reg::X(13), (Reg::X(16), Reg::INV, 16 * 6,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(14), Reg::X(15), (Reg::X(16), Reg::INV, 16 * 7,  MemAccCls::Offset))
				// ; LDP_RRM 	(Reg::X(16), Reg::X(17), (Reg::X(16), Reg::INV, 16 * 8,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(18), Reg::X(19), (Reg::X(16), Reg::INV, 16 * 9,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(20), Reg::X(21), (Reg::X(16), Reg::INV, 16 * 10, MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(22), Reg::X(23), (Reg::X(16), Reg::INV, 16 * 11, MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(24), Reg::X(25), (Reg::X(16), Reg::INV, 16 * 12, MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(26), Reg::X(27), (Reg::X(16), Reg::INV, 16 * 13, MemAccCls::Offset))
				// Note that we cannot corrupt kernelspace FP
				; LDR_RM 		(Reg::X(28), 			 (Reg::X(16), Reg::INV, 16 * 14, MemAccCls::Offset))
				; LDR_RM 		(Reg::X(30),  			 (Reg::X(16), Reg::INV, 16 * 15, MemAccCls::Offset))
				// Load X17 with userspace FP/SP and store it to SP + 8 * 8/9
				// FP <- [reg, #232], SP <- [reg, #248]
				; LDR_RM 		(Reg::X(17),  			 (Reg::X(16), Reg::INV,  8 * 29, MemAccCls::Offset))
				; STR_RM 		(Reg::X(17),  			 (Reg::SP,    Reg::INV,  8 * 8,  MemAccCls::Offset))
				; LDR_RM 		(Reg::X(17),  			 (Reg::X(16), Reg::INV,  8 * 31, MemAccCls::Offset))
				; STR_RM 		(Reg::X(17),  			 (Reg::SP,    Reg::INV,  8 * 9,  MemAccCls::Offset))
				// Finish up our context loading
				; LDP_RRM 		(Reg::X(16), Reg::X(17), (Reg::X(16), Reg::INV, 16 * 8,  MemAccCls::Offset))
				// We then create our virtual env
				; STP_RRM 		(Reg::X(12), Reg::X(13), (Reg::SP,    Reg::INV, 16 * 1,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(14), Reg::X(15), (Reg::SP,    Reg::INV, 16 * 2,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(16), Reg::X(17), (Reg::SP,    Reg::INV, 16 * 3,  MemAccCls::Offset))
				// Load the stable reg (x17 with userspace SP, x16 with userspace FP)
				; LDP_RRM 		(Reg::X(16), Reg::X(17), (Reg::SP,    Reg::INV, 16 * 4,  MemAccCls::Offset))
				// Branch to code entry, will be resolved later
				; NOP
			];

			// ! TEST
			utils::append(&mut final_code, &prologue).unwrap();
			pending_b_insns.insert(self.trans_entry_addr, (prologue.len() - 4, core::ptr::null_mut())).unwrap();
			
			// utils::append(&mut final_code, &PROLOGUE).unwrap();
			// pending_b_insns.insert(self.entry_addr, (PROLOGUE.len() - 4, core::ptr::null_mut())).unwrap();

			// Length guard for PROLOGUE
			if prologue.len() != PROLOGUE_LEN {
				panic!("Please update PROLOGUE_LEN to {:#03x} before proceeding\n", prologue.len());
			}

			// `epilogue` will be executed before returning to runtime.
			// All BL/BLR/RET/SVC instructions will be translated to branch to this epilogue before returning to UCA runtime.
			let epilogue = assem![
				// Update stable reg (x16 -> FP, x17 -> SP)
				; STP_RRM 		(Reg::X(16), Reg::X(17), (Reg::SP,    Reg::INV, 16 * 4,  MemAccCls::Offset))
				// Update pt_regs
				// Invariant: all special regs are saved on the stack so we can scratch with them
				// x16: *mut pt_regs, X17: *mut u64 for extra params
				; LDP_RRM 		(Reg::X(16), Reg::X(17), (Reg::SP,    Reg::INV, 16 * 11, MemAccCls::Offset))
				// Store extra params
				; STP_RRM 		(Reg::X(10), Reg::X(11), (Reg::X(17), Reg::INV, 16 * 0,  MemAccCls::Offset))
				// Move virtual env results to pt_regs
				// x12 x13
				; LDP_RRM 		(Reg::X(14), Reg::X(15), (Reg::SP,    Reg::INV, 16 * 1,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(14), Reg::X(15), (Reg::X(16), Reg::INV, 16 * 6,  MemAccCls::Offset))
				// x14 x15
				; LDP_RRM 		(Reg::X(14), Reg::X(15), (Reg::SP  ,  Reg::INV, 16 * 2,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(14), Reg::X(15), (Reg::X(16), Reg::INV, 16 * 7,  MemAccCls::Offset))
				// x16, x17
				; LDP_RRM 		(Reg::X(14), Reg::X(15), (Reg::SP,    Reg::INV, 16 * 3,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(14), Reg::X(15), (Reg::X(16), Reg::INV, 16 * 8,  MemAccCls::Offset))
				// Userspace SP and FP
				; LDR_RM 		(Reg::X(14),  			 (Reg::SP,    Reg::INV, 8 * 8,   MemAccCls::Offset))
				; STR_RM 		(Reg::X(14),  			 (Reg::X(16), Reg::INV, 8 * 29,  MemAccCls::Offset))
				; LDR_RM 		(Reg::X(14),  			 (Reg::SP,    Reg::INV, 8 * 9,   MemAccCls::Offset))
				; STR_RM 		(Reg::X(14),  			 (Reg::X(16), Reg::INV, 8 * 31,  MemAccCls::Offset))
				// Update all other regs.
				// We update the following regs so as to be able to continue handling BL/BLR/SVC instructions in UCA runtime.
				// x0-x8 are important for SVC and parameter passing, we can omit x9-x17
				; STP_RRM 		(Reg::X(0),  Reg::X(1),  (Reg::X(16), Reg::INV, 16 * 0,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(2),  Reg::X(3),  (Reg::X(16), Reg::INV, 16 * 1,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(4),  Reg::X(5),  (Reg::X(16), Reg::INV, 16 * 2,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(6),  Reg::X(7),  (Reg::X(16), Reg::INV, 16 * 3,  MemAccCls::Offset))
				; STR_RM 		(Reg::X(8),  		     (Reg::X(16), Reg::INV, 16 * 4,  MemAccCls::Offset))
				// And also callee-saved regs
				; STP_RRM 		(Reg::X(18), Reg::X(19), (Reg::X(16), Reg::INV, 16 * 9,  MemAccCls::Offset))
				; STP_RRM 		(Reg::X(20), Reg::X(21), (Reg::X(16), Reg::INV, 16 * 10, MemAccCls::Offset))
				; STP_RRM 		(Reg::X(22), Reg::X(23), (Reg::X(16), Reg::INV, 16 * 11, MemAccCls::Offset))
				; STP_RRM 		(Reg::X(24), Reg::X(25), (Reg::X(16), Reg::INV, 16 * 12, MemAccCls::Offset))
				; STP_RRM 		(Reg::X(26), Reg::X(27), (Reg::X(16), Reg::INV, 16 * 13, MemAccCls::Offset))
				// Don't move kernelspace FP into pt_regs!
				; STR_RM 		(Reg::X(28), 			 (Reg::X(16), Reg::INV, 16 * 14, MemAccCls::Offset))
				; STR_RM 		(Reg::X(30), 			 (Reg::X(16), Reg::INV, 16 * 15, MemAccCls::Offset))
				// Set our return value (return status in x9 -> x0)
				; MOV_RR 		(Reg::X(0), Reg::X(9))
				// Fulfill calling convention, we have to restore X18 though, strange...
				; LDR_RM 		(Reg::X(18),  			 (Reg::SP,    Reg::INV,  8 * 11, MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(19), Reg::X(20), (Reg::SP,    Reg::INV, 16 * 6,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(21), Reg::X(22), (Reg::SP,    Reg::INV, 16 * 7,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(23), Reg::X(24), (Reg::SP,    Reg::INV, 16 * 8,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(25), Reg::X(26), (Reg::SP,    Reg::INV, 16 * 9,  MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(27), Reg::X(28), (Reg::SP,    Reg::INV, 16 * 10, MemAccCls::Offset))
				; LDP_RRM 		(Reg::X(29), Reg::X(30), (Reg::SP,    Reg::INV, 16 * 12, MemAccCls::PstIndex))
				; RET_R 		(Reg::X(30))
			];

			// PROLOGUE and EPILOGUE are placed at the beginning of our final code, 
			// so later we can modify the resulting code more easily with known offset.

			// utils::append(&mut final_code, &EPILOGUE).unwrap();

			// ! TEST
			utils::append(&mut final_code, &epilogue).unwrap();

			// 0 is the signature address of EPILOGUE, all B insns with b_target == 0 will be resolved to branch to EPILOGUE.
			// As EPILOGUE is the end of PROLOGUE, it's offset is `prologue.len()`.
			// vlabels.insert(0, PROLOGUE.len()).unwrap();

			// ! TEST
			self.vlabels.insert(0, prologue.len()).unwrap();

			// Length guard for EPILOGUE
			if epilogue.len() != EPILOGUE_LEN {
				panic!("Please update EPILOGUE_LEN to {:#03x} before proceeding\n", epilogue.len());
			}
		}

		for i in 0..basic_blocks.len() {
			let curr_bb: &BasicBlock = &basic_blocks[i];
			if curr_bb.starting_addr == self.trans_entry_addr {
				// We have to keep tract of this to dynamically change the final B insn in PROLOGUE
				// NOTE: This is the ONLY place that self.entry_offset should be modified in one translation session.
				self.trans_entry_offset = final_code.len() + self.code_offset;
				if self.lift_entry_offset == 0 {
					// We set the value of `lift_entry_offset` for once only.
					self.lift_entry_offset = self.trans_entry_offset;
				}
			}

			// Check if this basic block is the B target of some previous B instruction(s)
			self.resolve_branch(&mut final_code, curr_bb.starting_addr, &pending_b_insns)?;
			
			for ii in 0..curr_bb.insns.len() {
				let insn_ptr: *mut cs_insn = curr_bb.insns[ii];
				let curr_addr = unsafe { (*insn_ptr).address };
				// We have to check if we already have a mapping for this address
				// to avoid double mapping for special insns (i.e. CBNZ/CBZ/TBNZ/TBZ).
				if curr_addr != 0 && self.vlabels.find(curr_addr).is_none() {
					// `vlabels` stores the real offset of virtual labels, helping us map userspace address to offset in xpage.
					let offset = final_code.len() + self.code_offset;
					// ! DEBUG
					if PRINT_VLABELS {
						pr_info!("Vlabel: {:#x} -> {:#x}\t", curr_addr, offset);
						pr_cont!("len {:#x} + ofst {:#x}\n", final_code.len(), self.code_offset);
					}
					self.vlabels.insert(curr_addr, offset);
				}

				// ! PENDING: merge the following branch resolution code with `resolve_branch()`
				match unsafe { Insn::from((*insn_ptr).id) } {
					Insn::ARM64_INS_B => {
						if let Op::IMM(b_target) = get_operand(insn_ptr, 0) {
							if let Some(target_offset) = self.vlabels.find(b_target as u64) {
								// `target_offset` is the real offset of the label
								// and `final_code.len() + self.code_offset` is the real offset of the current B insn
								let offset = target_offset as i32 - (final_code.len() + self.code_offset) as i32;
								let tmp = 
									match Cond::from(get_cc(insn_ptr)) {
										Cond::AL | Cond::NV => {
											assem![
												; B_I 		(offset as u32)
											]
										}
										cc => {
											assem![
												; BC_IC 	(offset as u32, cc)
											]
										}
									};
								utils::append(&mut final_code, &tmp).unwrap();
							} else {
								// We'll resolve branching to later basic blocks or EPILOGUE later.
								// Since we will only use relative offset within current `final_code`, we do NOT add `self.code_offset` to `final_code.len()`.
								pending_b_insns.insert(b_target as u64, (final_code.len(), insn_ptr));
								// Push in some paddings: NOP for easy identification of unresolved B insn
								utils::append(&mut final_code, &NOP_BYTES).unwrap();
							}
						} else {
							pr_err!("Wrong B operand\n");
							return Err(EFAULT);
						}
					}
					Insn::ARM64_INS_CBNZ => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							if let Op::IMM(b_target) = get_operand(insn_ptr, 1) {
								if let Some(target_offset) = self.vlabels.find(b_target as u64) {
									let offset = target_offset as i32 - (final_code.len() + self.code_offset) as i32;
									let tmp = assem![
										; CBNZ_RI 		(r, offset as u32)
									];
									utils::append(&mut final_code, &tmp).unwrap();
								} else {
									pending_b_insns.insert(b_target as u64, (final_code.len(), insn_ptr));
									utils::append(&mut final_code, &NOP_BYTES).unwrap();
								}
							} else {
								pr_err!("Wrong CBNZ operand 1\n");
								return Err(EFAULT);
							}
						} else {
							pr_err!("Wrong CBNZ operand 0\n");
							return Err(EFAULT);
						}
					}
					Insn::ARM64_INS_CBZ => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							if let Op::IMM(b_target) = get_operand(insn_ptr, 1) {
								if let Some(target_offset) = self.vlabels.find(b_target as u64) {
									let offset = target_offset as i32 - (final_code.len() + self.code_offset) as i32;
									let tmp = assem![
										; CBZ_RI 		(r, offset as u32)
									];
									utils::append(&mut final_code, &tmp).unwrap();
								} else {
									pending_b_insns.insert(b_target as u64, (final_code.len(), insn_ptr));
									utils::append(&mut final_code, &NOP_BYTES).unwrap();
								}
							} else {
								pr_err!("Wrong CBZ operand 1\n");
								return Err(EFAULT);
							}
						} else {
							pr_err!("Wrong CBZ operand 0\n");
							return Err(EFAULT);
						}
					}
					Insn::ARM64_INS_TBNZ => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							if let Op::IMM(test_bit) = get_operand(insn_ptr, 1) {
								if let Op::IMM(b_target) = get_operand(insn_ptr, 2) {
									if let Some(target_offset) = self.vlabels.find(b_target as u64) {
										let offset = target_offset as i32 - (final_code.len() + self.code_offset) as i32;
										let tmp = assem![
											; TBNZ_RII 		(r, test_bit as u32, offset as u32)
										];
										utils::append(&mut final_code, &tmp).unwrap();
									} else {
										pending_b_insns.insert(b_target as u64, (final_code.len(), insn_ptr));
										utils::append(&mut final_code, &NOP_BYTES).unwrap();
									}
								} else {
									pr_err!("Wrong TBNZ operand 2\n");
									return Err(EFAULT);
								}
							} else {
								pr_err!("Wrong TBNZ operand 1\n");
								return Err(EFAULT);
							}
						} else {
							pr_err!("Wrong TBNZ operand 0\n");
							return Err(EFAULT);
						}
					}
					Insn::ARM64_INS_TBZ => {
						if let Op::REG(r) = get_operand(insn_ptr, 0) {
							let r = Reg::from(r);
							if let Op::IMM(test_bit) = get_operand(insn_ptr, 1) {
								if let Op::IMM(b_target) = get_operand(insn_ptr, 2) {
									if let Some(target_offset) = self.vlabels.find(b_target as u64) {
										let offset = target_offset as i32 - (final_code.len() + self.code_offset) as i32;
										let tmp = assem![
											; TBZ_RII 		(r, test_bit as u32, offset as u32)
										];
										utils::append(&mut final_code, &tmp).unwrap();
									} else {
										pending_b_insns.insert(b_target as u64, (final_code.len(), insn_ptr));
										utils::append(&mut final_code, &NOP_BYTES).unwrap();
									}
								} else {
									pr_err!("Wrong TBZ operand 2\n");
									return Err(EFAULT);
								}
							} else {
								pr_err!("Wrong TBZ operand 1\n");
								return Err(EFAULT);
							}
						} else {
							pr_err!("Wrong TBZ operand 0\n");
							return Err(EFAULT);
						}
					}
					_ => {
						// Passing through
						utils::append(&mut final_code, &curr_bb.bytes[(ii * 4) .. ((ii + 1) * 4)]).unwrap();
					}
				}
			}

			// If this basic block is followed by some previously translated block,
			// let's say the ending address of this block is 0xaaaaaab0 
			// and we have translated some block starting at 0xaaaaaab4,
			// then we need to append an extra instruction to the current block to
			// make it branch to its subsequent basic block.
			// This extra instruction will also be inserted to vlabels.
			let subsequent_block_addr = curr_bb.ending_addr + 4;
			if let Some(subsequent_block_offset) = self.vlabels.find(subsequent_block_addr) {
				let curr_offset = final_code.len() + self.code_offset;
				// ! NOTE
				// This userspace address have 2 entries in vlabels, could be a problem
				// But normally we shall not search for the offset for this address.
				self.vlabels.insert(subsequent_block_addr, curr_offset).unwrap();
				// ! DEBUG
				if PRINT_VLABELS {
					pr_info!("Vlabel: {:#x} -> {:#x}\t", subsequent_block_addr, curr_offset);
					pr_cont!("len {:#x} + ofst {:#x}\n", final_code.len(), self.code_offset);
				}
				
				let offset = subsequent_block_offset - curr_offset;
				let b_basicblock = assem![
					; B_I 		(offset as u32)
				];
				utils::append(&mut final_code, &b_basicblock).unwrap();
			}
		}

		// ! DEBUG
		if PRINT_FINAL_CODE {
			utils::print_bytes(final_code.as_ptr(), final_code.len(), "Final code");
		}

		self.code_offset += final_code.len();

		Ok(final_code)
	}
}

pub(super) fn up() {
	cs_rust::up();
}

pub(super) fn down() {
	cs_rust::down();
}

/// Sorts a basic block array wrt starting address, insertion sort, ascending order
fn sort_basic_blocks(basic_blocks: &mut Vec<BasicBlock>) {
	for i in 1..basic_blocks.len() {
		let mut j = i;
		while j > 0 && basic_blocks[j].starting_addr < basic_blocks[j - 1].starting_addr {
			let pa = core::ptr::addr_of_mut!(basic_blocks[j]);
			let pb = core::ptr::addr_of_mut!(basic_blocks[j - 1]);
			unsafe { core::ptr::swap(pa, pb); }
			j -= 1;
		}
	}
}

fn analyze_insn(insn_ptr: *mut cs_insn) {
	let cnt = get_op_cnt(insn_ptr) as usize;
	for i in 0..cnt {
		match get_operand(insn_ptr, i) {
			Op::REG(r) => {
				let reg = Reg::from(r);
				if let Reg::X(xr) = reg {
					if xr == 9 || xr == 10 || xr == 11 {
						pr_alert!("x{} used at {:#x}\n", xr, unsafe { (*insn_ptr).address });
					}
				}
			}
			Op::MEM(r0, r1, _) => {
				let reg = Reg::from(r0);
				if let Reg::X(xr) = reg {
					if xr == 9 || xr == 10 || xr == 11 {
						pr_alert!("x{} used at {:#x}\n", xr, unsafe { (*insn_ptr).address });
					}
				}
				let reg = Reg::from(r1);
				if let Reg::X(xr) = reg {
					if xr == 9 || xr == 10 || xr == 11 {
						pr_alert!("x{} used at {:#x}\n", xr, unsafe { (*insn_ptr).address });
					}
				}
			}
			_ => {}
		}
	}
}

//! # Module `code_lifter`
//! 
//! NOTICE: This module is part of the UCA project 
//! 
//! It takes advantage of the functionalities provided by the KJIT framework 
//! to translate and lift the code starting from the entry address.

use core::sync::atomic::{AtomicPtr, Ordering};
use kernel::{pr_cont, prelude::*};
use kernel::sync::Arc;
use kernel::task::pt_regs;
#[macro_use]
use crate::assem;
use crate::trans::prelude::*;
use crate::utils::{self, x_page::XPage};
use super::ez_hash;

const NR_EXEC_INFOS: usize = 32;
pub(crate) static GLOBAL_LIFTER: AtomicPtr<CodeLifter> = AtomicPtr::new(core::ptr::null_mut());

// ! DEBUG
const DEBUG: bool = false;
const LIFT: bool = true;
const LOOP_LIMIT: usize = 2000;
const LIFT_LIMIT: usize = 1;
const PRINT_PRE_CODE: bool = false;
const PRINT_MODI_CODE: bool = false;

extern "C" {
	fn do_el0_svc(regs: *mut pt_regs);
}

/// ! PENDING: Each ExecInfo should have Mutex relation with each other
struct ExecInfo {
	pc: u64,
	pid: i32,
	xp: XPage,
	tr: Translator,
	status: bool,
}

impl Default for ExecInfo {
	fn default() -> Self {
	    Self {
			pc: 0,
			pid: 0,
			xp: XPage::new(),
			tr: Translator::new(),
			status: false,
		}
	}
}

impl ExecInfo {
	pub(crate) fn set_succ(&mut self) {
		self.status = true;
	}
	
	pub(crate) fn set_failed(&mut self) {
		self.status = false;
	}

	pub(crate) fn has_failed(&self) -> bool {
		!self.status
	}

	/// Updates the `ExecInfo`, setting status to SUCCESS
	pub(crate) fn update(
		&mut self, 
		pc: u64,
		pid: i32,
		xpage: XPage,
		translator: Translator,
	) {
		self.pc = pc;
		self.pid = pid;
		self.xp = xpage;
		self.tr = translator;
		self.status = true;
	}
}

pub(crate) struct CodeLifter {
	execs: Vec<ExecInfo>,
	session_cnt: usize,
}

impl CodeLifter {
	pub(crate) fn new() -> Self {
		let mut execs = Vec::with_capacity(NR_EXEC_INFOS, GFP_ATOMIC).unwrap();
        for _ in 0..NR_EXEC_INFOS {
            execs.push(ExecInfo::default(), GFP_ATOMIC).unwrap();
        }
		Self {
			execs,
			session_cnt: 0
		}
	}

	/// Called by `send_hot_svc()` in **svc_profiler.rs** to prepare for lifting.
	/// 
	/// This method interacts with the underlying `trans` module.
	pub(crate) fn prepare(&mut self, pc: u64, pid: i32, cpu: usize) {
		// Let reuse translated code for pc
		// ! PROBLEM: different mmap for different processes may pose a problem
		let pos = ez_hash(pc, pid) % NR_EXEC_INFOS;
		// let pos = ((pc as usize) >> 2) % NR_EXEC_INFOS;
		let exec: &mut ExecInfo = &mut self.execs[pos];
		if exec.pc == pc && exec.pid == pid {
		// if exec.pc == pc {
			// We have succeeded in translating this, nothing more to do.
			return;
		} else if let Ok(_) = utils::read_mem(pc, 4) {
			pr_info!("Hot SVC at {:#x} with PID {} on CPU {}\n", pc, pid, cpu);
			let mut t = Translator::new();
			if let Ok(code) = t.trans(pc) {
				exec.update(pc, pid, XPage::from_slice(&code), t);
			} else {
				pr_err!("Trans failed\n");
			}
		}
	}

	/// Tries to lift the code starting at `pc` if we have translated it before. Returns `Err` when impossible to lift.
	pub(crate) fn try_lift(&mut self, pc: u64, pid: i32, cpu: usize, regs: *mut pt_regs) -> Result<()> {
		let pos = ez_hash(pc, pid) % NR_EXEC_INFOS;
		// let pos = ((pc as usize) >> 2) % NR_EXEC_INFOS;
		let exec: &mut ExecInfo = unsafe { &mut *self.execs.as_mut_ptr().add(pos) };
		if exec.pc == pc && exec.pid == pid {
		// if exec.pc == pc {
			// We can always lift because we can always execute something and may be able to
			// explore new execution paths that actually lead up to the hot loop
			let new_b_insn = assem![
				; B_I 		((exec.tr.get_lift_entry_offset() - PROLOGUE_END) as u32)
			];
			exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

			self.session_cnt += 1;
			if self.session_cnt <= LIFT_LIMIT {
				// pr_alert!("get_lift_entry_offset: {}\n", exec.tr.get_lift_entry_offset());
				self.lift(exec, regs);
			}
			Ok(())
		} else {
			Err(EFAULT)
		}
	}

	/// Periodical printing
	fn can_print(&self) -> bool {
		DEBUG || self.session_cnt % (1 << 12) == 1
	}

	/// Executes the code passed in within kernel space
	fn lift(&mut self, exec: &mut ExecInfo, regs: *mut pt_regs) {
		const NR_EXT_PARAMS: usize = 2;
		let mut extra_params: Vec<u64> = Vec::with_capacity(NR_EXT_PARAMS, GFP_ATOMIC).unwrap();
		unsafe { extra_params.set_len(NR_EXT_PARAMS); }
		let xpage_ptr = exec.xp.as_ptr();
		let exec_func: extern "C" fn (*mut pt_regs, *mut u64) -> u64 = unsafe { 
			core::mem::transmute(xpage_ptr as *const _) 
		};

		let mut cnt = 0;
		let mut svc_loop_cnt = 0;
		if DEBUG {
			pr_info!("###### Lift session {} ######\n", self.session_cnt);
		}

		if !LIFT {
			// if self.can_print() {
				pr_info!("Ignoring with xpage len {}\n", exec.xp.len());
			// }
			return;
		}

		'lift:
		loop {
			// ! DEBUG
			if PRINT_PRE_CODE && cnt == LIFT_LIMIT.wrapping_sub(1) {
				utils::print_bytes(unsafe { exec.xp.as_ptr() }, exec.xp.len(), "Pre code");
			}

			// Lift!
			// if self.can_print() {
			// 	pr_info!("Lifting with xpage len {}n", exec.xp.len());
			// }
			// if DEBUG {
			// 	print_regs(regs);
			// }
			let ret_val = exec_func(regs, extra_params.as_mut_ptr());
			exec.set_succ();
			cnt += 1;

			let ret_status = RetStatus::from(ret_val & 0xFFFF);
			let imm_param: u64 = extra_params[0];
			// The address and offset of 'B to EPILOGUE'
			let b_insn_addr: u64 = extra_params[1];
			let b_insn_offset = (b_insn_addr as usize - xpage_ptr as usize);

			if DEBUG {
				match ret_status {
					RetStatus::RSvc => {
						pr_info!("{:?} at {:#x}\n", ret_status, b_insn_offset);

						unsafe { do_el0_svc(regs); }
						svc_loop_cnt += 1;
						let new_b_insn = assem![
							; B_I 		(((b_insn_offset + 4) - PROLOGUE_END) as u32)
						];
						exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

						if cnt >= LOOP_LIMIT {
							if let Some(resume_addr) = exec.tr.get_vlabels().find_val(b_insn_offset + 4) {
								unsafe {
									(*regs).__bindgen_anon_1.user_regs.pc = resume_addr;
								}
								break 'lift;
							} else {
								// Panics here rather than handing incorrect PC value to user space
								panic!("SVC: Unable to set pc value\n");
							}
						}
					}
					RetStatus::RBl => {
						pr_info!("{:?} at {:#x}", ret_status, b_insn_offset);
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// Known target
							pr_cont!(" to known target {:#x}\n", imm_param);
							// We are branching forward so we cannot underflow here.
							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						} else {
							// Unknown target
							// We can create a blacklist to avoid problematic control paths
							if (imm_param == 0xaaaaaab1b170) {
								pr_cont!(" to {:#x} in blacklist, back to userspace\n", imm_param);
								exec.set_failed();
							} else {
								if let Ok(jit) = exec.tr.trans(imm_param) {
									exec.xp.append(&jit);

									let target_offset = exec.tr.get_trans_entry_offset();
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
									
									pr_info!("BL to unknown target {:#x} at {:#x}\n", imm_param, target_offset);
								} else {
									pr_err!("BL JIT failed for {:#x}\n", imm_param);
									exec.set_failed();
								}
							}
						}

						let userspace_lr = exec.tr.get_vlabels().find_val(b_insn_offset + 4).unwrap();
						unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] = userspace_lr; }
						if exec.has_failed() || cnt >= LOOP_LIMIT {
							unsafe {
								(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
							}
							break 'lift;
						}
					}
					RetStatus::RBlr => {
						pr_info!("{:?} at {:#x}", ret_status, b_insn_offset);
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// Known target
							pr_cont!(" to known target {:#x}\n", imm_param);
							// We are branching forward so we cannot underflow here.
							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						} else {
							// Unknown target
							if let Ok(jit) = exec.tr.trans(imm_param) {
								exec.xp.append(&jit);

								let target_offset = exec.tr.get_trans_entry_offset();
								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
								
								pr_info!("BLR to unknown target {:#x} at {:#x}\n", imm_param, target_offset);
							} else {
								pr_err!("BLR JIT failed for {:#x}\n", imm_param);
								exec.set_failed();
							}
						}

						let userspace_lr = exec.tr.get_vlabels().find_val(b_insn_offset + 4).unwrap();
						unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] = userspace_lr; }
						if exec.has_failed() || cnt >= LOOP_LIMIT {
							unsafe {
								(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
							}
							break 'lift;
						}
					}
					RetStatus::RBr => {
						pr_info!("{:?} at {:#x}", ret_status, b_insn_offset);
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// Known target
							pr_cont!(" to known target {:#x}\n", imm_param);

							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						} else {
							// Unknown target
							if let Ok(jit) = exec.tr.trans(imm_param) {
								let target_offset = exec.tr.get_trans_entry_offset();
								exec.xp.append(&jit);
								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
								pr_info!("BR to {:#x} at {:#x}\n", imm_param, target_offset);
							} else {
								pr_err!("BR JIT failed for {:#x}\n", imm_param);
								exec.set_failed();
							}
						}

						if cnt >= LOOP_LIMIT || exec.has_failed() {
							unsafe {
								(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
							}
							break 'lift;
						}
					}
					RetStatus::RRet => {
						pr_info!("{:?} at {:#x}", ret_status, b_insn_offset);

						if imm_param & (1 << 63) != 0 {
							panic!("Kernelspace return address found in DEBUG mode\n");
						} else {
							if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
								// Know target, continue lifted execution
								pr_cont!(" to known target {:#x}\n", imm_param);

								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
							} else {
								// Unknown target, JIT only when no loop on SVC has been detected
								if exec.tr.found_loop() {
									pr_cont!(" to {:#x}, back to userspace\n", imm_param);
									unsafe {
										(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
									}
									break 'lift;
								}

								if let Ok(jit) = exec.tr.trans(imm_param) {
									let target_offset = exec.tr.get_trans_entry_offset();
									exec.xp.append(&jit);
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
									pr_info!("RET to {:#x} at {:#x}\n", imm_param, target_offset);
								} else {
									pr_err!("RET JIT failed for {:#x}\n", imm_param);
									exec.set_failed();
								}
							}

							if cnt >= LOOP_LIMIT || exec.has_failed() {
								unsafe {
									(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
								}
								break 'lift;
							}
						}
					}
					RetStatus::RMem => {
						// `ret_val` is divided into 3 parts: 0..16 is `RetStatus`, 16..32 is r0, 32..64 is i0
						// imm_param stores the value of the offset register
						let r0 = Reg::from(((ret_val >> 16) & 0xFFFF) as u32);
						let i0 = ((ret_val >> 32) & 0xFFF) as u32;
						let addr = imm_param + i0 as u64;
						let byte: u8 = utils::read_mem(addr, 1).unwrap()[0];
						pr_info!("{:?} at {:#x}, got {:#x}\n", ret_status, addr, byte);
						// Set the value in the target register
						unsafe { (*regs).__bindgen_anon_1.user_regs.regs[u32::from(r0) as usize] = byte as u64; }

						// Resumes execution at the next insn
						let new_b_insn = assem![
							; B_I 		(((b_insn_offset + 4) - PROLOGUE_END) as u32)
						];
						exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

						// ! PENDING: return to userspace on LOOP_LIMIT
					}
					RetStatus::RDebug => {
						// This section can ONLY be reached in DEBUG mode
						pr_info!("{:?} at {:#x}", ret_status, b_insn_offset);
						// We only return from the end of each basic block when debugging 
						// 1. extra_param[0] holds the b target value
						// 2. extra_param[1] holds the b_insn_addr
						// 3. Other info is contained within 64 bits of `ret_val`
						let nzcv = (ret_val >> 28) & 0xF;
						let (n, z, c, v) = ((nzcv >> 3) & 0b1, (nzcv >> 2) & 0b1, (nzcv >> 1) & 0b1, (nzcv >> 0) & 0b1);
						let cc = Cond::from(((ret_val >> 32) & 0xF) as u32);
						let branch = match cc {
							Cond::EQ => { z != 0 }
							Cond::NE => { z == 0 }
							Cond::CS => { c != 0 }
							Cond::CC => { c == 0 }
							Cond::MI => { n != 0 }
							Cond::PL => { n == 0 }
							Cond::VS => { v != 0 }
							Cond::VC => { v == 0 }
							Cond::HI => { c != 0 && z == 0 }
							Cond::LS => { c == 0 || z != 0 }
							Cond::GE => { n == v }
							Cond::LT => { n != v }
							Cond::GT => { z == 0 && n == v }
							Cond::LE => { z != 0 && n != v }
							Cond::AL |
							Cond::NV => { true }
						};
						if branch {
							if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
								pr_cont!(" to {:#x} at {:#x}\n", imm_param, target_offset);
								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
							} else {
								panic!("B: Wrong branching target\n");
							}
						} else {
							pr_cont!(", continue at {:#x}\n", b_insn_offset + 4);
							let new_b_insn = assem![
								; B_I 		(((b_insn_offset + 4) - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						}

						if cnt >= LOOP_LIMIT {
							if branch {
								unsafe {
									(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
								}
							} else {
								if let Some(resume_addr) = exec.tr.get_vlabels().find_val(b_insn_offset + 4) {
									unsafe {
										(*regs).__bindgen_anon_1.user_regs.pc = resume_addr;
									}
								} else {
									panic!("B: Unable to set pc/lr value\n");
								}
							}
							break 'lift;
						}
					}
					RetStatus::RInv => {
						panic!("Invalid return value\n");
					}
				}
			} else {
				match ret_status {
					RetStatus::RSvc => {
						// ! TEST
						if svc_loop_cnt % (LOOP_LIMIT / 10) == 0 {
							pr_info!("SVC\n")
						}

						unsafe { do_el0_svc(regs); }
						svc_loop_cnt += 1;
						let new_b_insn = assem![
							; B_I 		(((b_insn_offset + 4) - PROLOGUE_END) as u32)
						];
						exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						if cnt >= LOOP_LIMIT {
							if let Some(resume_addr) = exec.tr.get_vlabels().find_val(b_insn_offset + 4) {
								unsafe { (*regs).__bindgen_anon_1.user_regs.pc = resume_addr; }
								break 'lift;
							} else {
								// Panics here rather than handing incorrect PC value to user space
								panic!("SVC: Unable to set pc value\n");
							}
						}
					}
					RetStatus::RBl => {
						// `imm_param` is the userspace bl target address
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// We are branching forward so we cannot underflow here.
							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
							// Modify the code for subsequent execution without runtime
							// We could be branching backward so cast usize to i32 to avoid underflow
							let offset = target_offset as i32 - b_insn_offset as i32;
							let new_bl_insn = assem![
								; BL_I 		(offset as u32)
							];
							exec.xp.update_insn(b_insn_offset, &new_bl_insn);
						} else {
							// Unknown target, JIT only when no loop on SVC has been detected
							if !exec.tr.found_loop() {
								// We can create a blacklist to avoid problematic control paths
								if let Ok(jit) = exec.tr.trans(imm_param) {
									exec.xp.append(&jit);

									let target_offset = exec.tr.get_trans_entry_offset();
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

									let offset = target_offset as i32 - b_insn_offset as i32;
									let new_bl_insn = assem![
										; BL_I 		(offset as u32)
									];
									exec.xp.update_insn(b_insn_offset, &new_bl_insn);
								} else {
									exec.set_failed();
								}
							} else {
								exec.set_failed();
							}
						}

						// We always set lr to kernel space address and shall rest assured that
						// this will get converted to user space address before returning
						unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] = b_insn_addr + 4; }
						if exec.has_failed() || cnt >= LOOP_LIMIT {
							unsafe { (*regs).__bindgen_anon_1.user_regs.pc = imm_param; }
							break 'lift;
						}
					}
					RetStatus::RBlr => {
						// ! PENDING
						if imm_param & (1 << 63) != 0 {
							panic!("Unsupported BLR address\n");
						}
						// `imm_param` is the userspace blr target address
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// Known target
							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						} else {
							// Unknown target, only exploring when no loop has been detected
							if !exec.tr.found_loop() {
								if let Ok(jit) = exec.tr.trans(imm_param) {
									exec.xp.append(&jit);

									let target_offset = exec.tr.get_trans_entry_offset();
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
								} else {
									exec.set_failed();
								}
							} else {
								exec.set_failed();
							}
						}

						unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] = b_insn_addr + 4; }
						if exec.has_failed() || cnt >= LOOP_LIMIT {
							unsafe {
								(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
							}
							break 'lift;
						}
					}
					RetStatus::RBr => {
						// ! PENDING
						if imm_param & (1 << 63) != 0 {
							panic!("Unsupported BR address\n");
						}

						// Well, `imm_param` is still the br target
						if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
							// Known target
							let new_b_insn = assem![
								; B_I 		((target_offset - PROLOGUE_END) as u32)
							];
							exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
						} else {
							// Unknown target, only exploring when no loop has been detected
							if !exec.tr.found_loop() {
								if let Ok(jit) = exec.tr.trans(imm_param) {
									let target_offset = exec.tr.get_trans_entry_offset();
									exec.xp.append(&jit);
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);
								} else {
									exec.set_failed();
								}
							} else {
								exec.set_failed();
							}
						}

						// This time lr is left untouched
						if cnt >= LOOP_LIMIT || exec.has_failed() {
							unsafe {
								(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
							}
							break 'lift;
						}
					}
					RetStatus::RRet => {
						// `imm_param` is the return target, can be in userspace and kernel space
						// ! PROBLEM: the stack frame may contain kernelspace address upon returning
						// Though we shall not return in normal mode unless we have popped this stack frame
						// But NOT so when we encountered some error.
						if imm_param & (1 << 63) == 0 {
							// Userspace address
							if let Some(target_offset) = exec.tr.get_vlabels().find(imm_param) {
								// Know target, continue lifted execution
								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

								// ! PROBLEM: This is for demonstration purpose ONLY now
								// let new_ret_insn = assem![
								// 	; RET_R 		(Reg::X(30))
								// ];
								// exec.xp.update_insn(b_insn_offset, &new_ret_insn);
							} else {
								// Unknown target, JIT only when no loop on SVC has been detected
								if exec.tr.found_loop() {
									unsafe {
										(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
									}
									break 'lift;
								}

								if let Ok(jit) = exec.tr.trans(imm_param) {
									let target_offset = exec.tr.get_trans_entry_offset();
									exec.xp.append(&jit);
									let new_b_insn = assem![
										; B_I 		((target_offset - PROLOGUE_END) as u32)
									];
									exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

									// ! PENDING: If we want to RET directly inside translated code,
									// we have to keep a list and search through it for actual return target.
									// Directly changing the insn to RET will NOT work.
									// let new_ret_insn = assem![
									// 	; RET_R 		(Reg::X(30))
									// ];
									// exec.xp.update_insn(b_insn_offset, &new_ret_insn);
								} else {
									exec.set_failed();
								}
							}
							
							if cnt >= LOOP_LIMIT || exec.has_failed() {
								unsafe {
									(*regs).__bindgen_anon_1.user_regs.pc = imm_param;
								}
								break 'lift;
							}
						} else {
							// Kernelspace address
							let target_offset = imm_param as usize - xpage_ptr as usize;
							if let Some(resume_addr) = exec.tr.get_vlabels().find_val(target_offset) {
								let new_b_insn = assem![
									; B_I 		((target_offset - PROLOGUE_END) as u32)
								];
								exec.xp.update_insn(PROLOGUE_END, &new_b_insn);

								// ! PROBLEM: See above note
								// let new_ret_insn = assem![
								// 	; RET_R 		(Reg::X(30))
								// ];
								// exec.xp.update_insn(b_insn_offset, &new_ret_insn);

								if cnt >= LOOP_LIMIT || exec.has_failed() {
									unsafe {
										(*regs).__bindgen_anon_1.user_regs.pc = resume_addr;
									}
									break 'lift;
								}
							} else {
								panic!("Returning to unidentified kernel address\n");
							}
						}

					}
					RetStatus::RMem   |
					RetStatus::RDebug |
					RetStatus::RInv   => {
						panic!("Invalid return value under NORMAL mode\n");
					}
				}
			}
		}

		// We should make sure that lr in pt_regs is userspace address upon returning.
		let lr = unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] };
		if lr & (1 << 63) != 0 {
			if let Some(userspace_lr) = exec.tr.get_vlabels().find_val(lr as usize - xpage_ptr as usize) {
				unsafe { (*regs).__bindgen_anon_1.user_regs.regs[30] = userspace_lr; }
			} else {
				panic!("Unable to recover userspace lr\n");
			}
		}

		// If we reach this place, it means that we have at least succeeded in 
		// lifting something, so we set status to be true. The logic here is that 
		// we can choose to ignore paths containing insns that we don't support 
		// and run only those of which we support everything.
		exec.set_succ();

		if self.can_print() {
			if PRINT_MODI_CODE {
				utils::print_bytes(unsafe { exec.xp.as_ptr() }, exec.xp.len(), "Modi code");
			}
			// print_regs(regs);
		}
		// if self.can_print() {
			pr_info!("Session {}, left with cnt {}\n", self.session_cnt, cnt);
		// }
	}
}

fn print_regs(regs: *mut pt_regs) {
	pr_info!("Regs: \n");
	for i in 0..31 {
		pr_cont!("\tX{:02}: {:012x}", i, unsafe { (*regs).__bindgen_anon_1.user_regs.regs[i] });
		if i % 4 == 3 {
			pr_cont!("\n");
		}
	}
	pr_cont!("\n\tSP:  {:012x}\tPC:  {:012x}", 
				unsafe { (*regs).__bindgen_anon_1.user_regs.sp },
				unsafe { (*regs).__bindgen_anon_1.user_regs.pc });
}

/// Initializes the CodeLifter instance
pub(crate) fn up() {
	let lifter = Arc::new(CodeLifter::new(), GFP_ATOMIC).unwrap();
	let lifter_ptr = Arc::into_raw(lifter) as *mut CodeLifter;
	GLOBAL_LIFTER.store(lifter_ptr, Ordering::SeqCst);
}

// Shuts down the CodeLifter
pub(crate) fn down() {
	let lifter_ptr = GLOBAL_LIFTER.swap(core::ptr::null_mut(), Ordering::SeqCst);
	unsafe { Arc::from_raw(lifter_ptr); }
}

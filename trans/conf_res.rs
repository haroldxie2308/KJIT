//! # Goal
//! 
//! This module aims to resolve conflicting regs for special registers and generating the output machine code for each instruction.

use kernel::prelude::*;

#[macro_use]
use super::*;
use crate::utils;

// Special registers: X12, X13, X14, X15, X16, X17 + SP
const SPECIAL_REGS: u64 = 0b1_0000_0000_0000_0011_1111_0000_0000_0000;
// Stable registers: X17 -> SP, X16 -> FP
const STABLE_REGS: u64  = 0b0000_0000_0000_0011_0000_0000_0000_0000;

pub(crate) fn is_special_reg(r: Reg) -> bool {
	(u64::from(r) & SPECIAL_REGS) != 0
}

pub(crate) fn is_stable_reg(r: Reg) -> bool {
	(u64::from(r) & STABLE_REGS) != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RwStatus {
	Read,
	Write,
	Undecided,
}

/// Each basic block should be coupled with a ConfResolver
/// 
/// Resolves special register conflicts
pub(crate) struct ConfResolver {
	reg_map: MultiMap<Reg, Reg>,
	reg_stack_map: MultiMap<Reg, u32>,
	status: bool,
	insns_pending_free: Vec<*mut cs_insn>,
}

impl Drop for ConfResolver {
	fn drop(&mut self) {
	    if self.status {
	    	// If we have succeeded in resolving reg conflict for one basic block, we can free extraneous insns
	    	free_insns(&self.insns_pending_free);
	    }
	}
}

impl ConfResolver {
	pub(crate) fn new() -> Self {
		let mut reg_map = MultiMap::new();
		// Only scan for GPRs, now 6 GPRs are used
		for i in 0..32 {
			let reg_mask: u64 = 0b1 << i;
			if reg_mask & SPECIAL_REGS != 0 {
				let tmp = Reg::from(reg_mask);
				match tmp {
					Reg::X(16) => {
						// Stable mapping
						reg_map.insert(Reg::from(reg_mask), Reg::X(29)).unwrap()
					}
					Reg::X(17) => {
						// Stable mapping
						reg_map.insert(Reg::from(reg_mask), Reg::SP).unwrap()
					}
					_ => {
						reg_map.insert(Reg::from(reg_mask), Reg::INV).unwrap()
					}
				}
			}
		}

		// Mapping each register to their position on the stack, offset w.r.t. SP
		let mut reg_stack_map = MultiMap::new();
		reg_stack_map.insert(Reg::X(12), 0x10);
		reg_stack_map.insert(Reg::X(13), 0x18);
		reg_stack_map.insert(Reg::X(14), 0x20);
		reg_stack_map.insert(Reg::X(15), 0x28);
		reg_stack_map.insert(Reg::X(16), 0x30);
		reg_stack_map.insert(Reg::X(17), 0x38);
		reg_stack_map.insert(Reg::SP,    0x40);
		reg_stack_map.insert(Reg::X(29), 0x48);

		Self {
			reg_map,
			reg_stack_map,
			status: true,
			insns_pending_free: Vec::new(),
		}
	}

	/// Register Analysis to generate conflicting regs and their RW status in this insn, returned map may contain both x_regs and w_regs!
	fn reg_analy(&mut self, insn_ptr: *mut cs_insn) -> Result<MultiMap<Reg, RwStatus>> {
		// We want to update `occupied_regs` field of each basic block.
		// To achieve this, we need to traverse the basic blocks backwards, examine the instruction at each step to figure out 
		// which Regs are READ and which are WRITE.
		let mut ret = MultiMap::new();
		let op_cnt = get_op_cnt(insn_ptr);
		let insn_type = unsafe { Insn::from((*insn_ptr).id) };

		match op_cnt {
			0 => {
				// We have nothing to do for insn with no operand
			}
			1 => {
				let op0 = get_operand(insn_ptr, 0);
				match op0 {
					Op::REG(r0) => {
						// # READ
						let r0 = Reg::from(r0);
						if is_special_reg(r0) {
							ret.insert(r0, RwStatus::Read).unwrap();
						}

						// ! TEST
						if let Reg::D(_) = r0 {
							pr_err!("D reg for {:?}", insn_type);
							return Err(ERANGE);
						}
					}
					Op::INVAL => {
			        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
			        }
					_ => {
						// ! PENDING: Other operands are not supported yet
					}
				}
			}
			2 => {
				let insn_type = insn_type;
				match insn_type {
					// All comparisons and test use both operands as READ
					Insn::ARM64_INS_CMP   |
					Insn::ARM64_INS_CMPEQ |
					Insn::ARM64_INS_CMPGE |
					Insn::ARM64_INS_CMPGT |
					Insn::ARM64_INS_CMPHI |
					Insn::ARM64_INS_CMPHS |
					Insn::ARM64_INS_CMPLE |
					Insn::ARM64_INS_CMPLO |
					Insn::ARM64_INS_CMPLS |
					Insn::ARM64_INS_CMPLT |
					Insn::ARM64_INS_CMPNE |
					Insn::ARM64_INS_CMPP  |
					Insn::ARM64_INS_TST   => {
						for iii in 0..2 {
							match get_operand(insn_ptr, iii) {
								Op::REG(r0) => {
									// READ
									let r0 = Reg::from(r0);
									if is_special_reg(r0) {
										ret.insert(r0, RwStatus::Read).unwrap();
									}
								}
								Op::IMM(_) => {
									// IMM value, passing through
								}
						        Op::INVAL => {
						        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
						        }
						        _ => {
									pr_warn!("Unsupported CMP op\n");
								}
							}
						}
					}
					Insn::ARM64_INS_MOV  |
					Insn::ARM64_INS_MOVZ => {
						match get_operand(insn_ptr, 0) {
							Op::REG(r0) => {
								// Write
								let r0 = Reg::from(r0);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Write).unwrap();
								}
							}
							Op::INVAL => {
					        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
					        }
							_ => { 
								pr_warn!("Unsupported STR op\n");
							}
						}
						match get_operand(insn_ptr, 1) {
							Op::REG(r0) => {
								// Read
								let r0 = Reg::from(r0);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Read).unwrap();
								}
							}
							Op::MEM(r0, r1, i0) => {
								let r0 = Reg::from(r0);
								let r1 = Reg::from(r1);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Read).unwrap();
								}
								if is_special_reg(r1) {
									ret.insert(r1, RwStatus::Read).unwrap();
								}
							}
					        Op::INVAL => {
					        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
					        }
					        _ => {}
						}
					}
					_ => {
						// ! PENDING: Optimization possible with few exceptions above
						// We now set every register to be READ
						match get_operand(insn_ptr, 0) {
							Op::REG(r0) => {
								// # READ
								let r0 = Reg::from(r0);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Read).unwrap();
								}

								// ! TEST
								if let Reg::D(_) = r0 {
									pr_err!("D reg for {:?}", insn_type);
									return Err(ERANGE);
								}
							}
							Op::INVAL => {
					        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
					        }
							_ => {}
						}
						match get_operand(insn_ptr, 1) {
							Op::REG(r0) => {
								// # READ
								let r0 = Reg::from(r0);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Read).unwrap();
								}

								// ! TEST
								if let Reg::D(_) = r0 {
									pr_err!("D reg for {:?}", insn_type);
									return Err(ERANGE);
								}
							}
							Op::MEM(r0, r1, i0) => {
								// # READ
								let r0 = Reg::from(r0);
								if is_special_reg(r0) {
									ret.insert(r0, RwStatus::Read).unwrap();
								}
								let r1 = Reg::from(r1);
								if is_special_reg(r1) {
									ret.insert(r1, RwStatus::Read).unwrap();
								}
							}
					        Op::INVAL => {
					        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
					        }
					        _ => {}
						}
					}
				}
			}
			3 | 4 => {
				// The fourth Op is IMM and is only encountered in LDP/STP insns, so we just don't care
				// match (get_operand(insn_ptr, 0), get_operand(insn_ptr, 1), get_operand(insn_ptr, 2)) {
				// 	(Op::REG(r0), Op::REG(r1), Op::REG(r2)) => {
				// 		// # WRITE
				// 		let r0 = Reg::from(r0);
				// 		if is_special_reg(r0) {
				// 			ret.insert(r0, RwStatus::Write).unwrap();
				// 		}
				// 		// # READ
				// 		let r1 = Reg::from(r1);
				// 		if is_special_reg(r1) {
				// 			ret.insert(r1, RwStatus::Read).unwrap();
				// 		}
				// 		let r2 = Reg::from(r2);
				// 		if is_special_reg(r2) {
				// 			ret.insert(r2, RwStatus::Read).unwrap();
				// 		}
				// 	}
				// 	(Op::REG(r0), Op::REG(r1), Op::IMM(_)) => {
				// 		// # WRITE
				// 		let r0 = Reg::from(r0);
				// 		if is_special_reg(r0) {
				// 			ret.insert(r0, RwStatus::Write).unwrap();
				// 		}
				// 		// # READ
				// 		let r1 = Reg::from(r1);
				// 		if is_special_reg(r1) {
				// 			ret.insert(r1, RwStatus::Read).unwrap();
				// 		}
				// 	}
				// 	(Op::REG(r0), Op::REG(r1), Op::MEM(r2, r3, _)) => {
				// 		match insn_type {
				// 			Insn::ARM64_INS_LDP => {
				// 				// # WRITE
				// 				let r0 = Reg::from(r0);
				// 				if is_special_reg(r0) {
				// 					ret.insert(r0, RwStatus::Write).unwrap();
				// 				}
				// 				let r1 = Reg::from(r1);
				// 				if is_special_reg(r1) {
				// 					ret.insert(r1, RwStatus::Write).unwrap();
				// 				}

				// 				// # READ
				// 				let r2 = Reg::from(r2);
				// 				if is_special_reg(r2) {
				// 					ret.insert(r2, RwStatus::Read).unwrap();
				// 				}
				// 				let r3 = Reg::from(r3);
				// 				if is_special_reg(r3) {
				// 					ret.insert(r3, RwStatus::Read).unwrap();
				// 				}
				// 			}
				// 			_ => {
				// 				// # READ
				// 				let r0 = Reg::from(r0);
				// 				if is_special_reg(r0) {
				// 					ret.insert(r0, RwStatus::Read).unwrap();
				// 				}
				// 				let r1 = Reg::from(r1);
				// 				if is_special_reg(r1) {
				// 					ret.insert(r1, RwStatus::Read).unwrap();
				// 				}
				// 				let r2 = Reg::from(r2);
				// 				if is_special_reg(r2) {
				// 					ret.insert(r2, RwStatus::Read).unwrap();
				// 				}
				// 				let r3 = Reg::from(r3);
				// 				if is_special_reg(r3) {
				// 					ret.insert(r3, RwStatus::Read).unwrap();
				// 				}
				// 			}
				// 		}
				// 	}
				// 	(Op::REG(r0), Op::IMM(_), Op::IMM(_)) => {
				// 		// TBNZ/TBZ
				// 		let r0 = Reg::from(r0);
				// 		if is_special_reg(r0) {
				// 			ret.insert(r0, RwStatus::Read).unwrap();
				// 		}
				// 	}
				// 	(a, b, c) => {
				// 		pr_warn!("Unsupported 3-Op pattern, {:?} {:?} {:?} {:?}\n",
				// 							insn_type, a, b, c); 
				// 	}
				// }
				// ! WARNING: we now try a naive implementation, but the above more advanced implementation will halt my program under certain circumstances
				for i in 0..3 {
					match get_operand(insn_ptr, i) {
						Op::REG(r0) => {
							// # READ
							let r0 = Reg::from(r0);
							if is_special_reg(r0) {
								ret.insert(r0, RwStatus::Read).unwrap();
							}

							// ! TEST
							if let Reg::D(_) = r0 {
								pr_err!("D reg for {:?}", insn_type);
								return Err(ERANGE);
							}
						}
						Op::MEM(r0, r1, i0) => {
							// # READ
							let r0 = Reg::from(r0);
							if is_special_reg(r0) {
								ret.insert(r0, RwStatus::Read).unwrap();
							}
							let r1 = Reg::from(r1);
							if is_special_reg(r1) {
								ret.insert(r1, RwStatus::Read).unwrap();
							}
						}
				        Op::INVAL => {
				        	pr_warn!("Unsupported Op for {:?}\n", insn_type);
				        }
				        _ => {}
					}
				}
			}
			_ => {
				pr_warn!("Too many operands, unsupported yet\n");
			}
		}

		Ok(ret)
	}

	/// Find the corresponding mapped reg if exists, otherwise return the original reg.
	/// Also takes care of w_reg casting.
	fn map_reg(&self, r: Reg) -> Reg {
		// self.reg_map: physical reg -> virtual reg
		// We intend to find the physical one with this function
		if let Some(ret) = self.reg_map.find_val(r.to_x_reg()) {
			if let Reg::W(_) = r {
				match ret {
					Reg::X(x_reg) => Reg::W(x_reg),
					Reg::SP   |
					Reg::W(_) |
					_  => {
						pr_err!("map_reg error\n");
						Reg::W(0)
					}
				}
			} else {
				ret
			}
		} else {
			r
		}
	}

	/// Finds an unused physical register for the given virtual register.
	/// 
	/// Returns `Some(pysical_reg)` on success, `None` otherwise.
	fn find_avail_reg_for(&mut self, vreg: Reg) -> Option<Reg> {
		if let Some(preg) = self.reg_map.find_val(Reg::INV) {
			// We've succeeded in finding a free physical register
			self.reg_map[preg] = vreg.to_x_reg();
			Some(preg)
		} else {
			None
		}
	}

	/// Register Conflict Resolution
	/// 
	/// Resolves register conflicts by generating backup/restore instructions alongside with the modified insn itself
	pub(crate) fn resolve(&mut self, insn_ptr: *mut cs_insn, insn_bytes: &[u8]) -> Result<(Vec<*mut cs_insn>, Vec<u8>)> {
		let conf_regs = self.reg_analy(insn_ptr)?;
		
		// final result: prefix + reg_mapped + suffix
		let mut reg_mapped_insn = Vec::new();
		let mut reg_mapped_bytes = Vec::new();

		// If we have no conflicting regs, just pass through (early return)
		if conf_regs.is_empty() {
			reg_mapped_insn.push(insn_ptr, GFP_ATOMIC).unwrap();
			utils::append(&mut reg_mapped_bytes, insn_bytes).unwrap();
			return Ok((reg_mapped_insn, reg_mapped_bytes));
		}

		// Otherwise, we resolve the conflicts and map the regs.
		// `pending` contains virtual registers waiting to be mapped to physical ones.
		let mut pending = Vec::new();
		let conf_reg_items = conf_regs.items();
		for i in 0..conf_reg_items.len() {
			let (reg, rw_status): (Reg, RwStatus) = conf_reg_items[i];
			if self.reg_map.find_val(reg.to_x_reg()).is_none() {
				// If we haven't assigned a physical register to `reg`
				pending.push((reg, rw_status), GFP_ATOMIC).unwrap()
			}
		}

		let mut prefix_bytes = Vec::new();
		let mut prefix_insns = Vec::new();
		let mut suffix_bytes = Vec::new();
		let mut suffix_insns = Vec::new();

		let insn_addr = unsafe { (*insn_ptr).address };

		while let Some((vreg, rw_status)) = pending.pop() {
			if let Some(preg) = self.find_avail_reg_for(vreg) {
				if rw_status != RwStatus::Write {
					// As we process conflicts and do lookups all in x_reg,
					// we might need to cast the regs before generating the real instrcution bytes.
					// But for load and backup insns, we just load/backup all 8 bytes
					let pref = assem![
						// We load the physical register found with its newly mapped virtual reg value directly
						; LDR_RM 		(preg, (Reg::SP, Reg::INV, self.reg_stack_map.find(vreg.to_x_reg()).unwrap(), MemAccCls::Offset))
					];
					utils::append(&mut prefix_bytes, &pref).unwrap();
					utils::append(&mut prefix_insns, &disasm_preserve_first_addr(pref.as_ptr(), pref.len(), insn_addr).unwrap()).unwrap();
				}
			} else {
				// ! PENDING: evict some reg_in_use to allow remapping
				// But I think this should be done after register usage analysis is available.
				self.status = false;
				panic!("Not enough physical register available for insn at {:#x}\n", insn_addr);
			}
		}

		if !self.status {
			return Err(EFAULT);
		}

		// Map the registers -- We have to do this whether `pending` is empty or not.
		// ! PENDING: Support all instructions that we can handle in mod `assem`.
		let mut mapd_insn = Vec::new();
		match unsafe { Insn::from((*insn_ptr).id) } {
			Insn::ARM64_INS_ADD => {
				// 2 possibilities: RRR, RRI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; ADD_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							Op::IMM(i0) => {
								mapd_insn = assem![
									; ADD_RRI 		(mapped_r0, mapped_r1, i0 as u32)
								];
							}
							_ => {
								pr_err!("Impossible ADD operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_ADDS => {
				// ! QUESTION: RRR, do we have a RRI variant? 
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; ADDS_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported ADDS operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_ADR => {
				// RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						mapd_insn = assem![
							; ADR_RI 		(mapped_r0, i0 as u32)
						];
					} else {
						pr_err!("Incorrect ADR operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_ADRP => {
				// RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						mapd_insn = assem![
							; ADRP_RI 		(mapped_r0, i0 as u32)
						];
					} else {
						pr_err!("Incorrect ADRP operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_AND => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; AND_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported AND operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_BLR => {
				// R
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					mapd_insn = assem![
						; BLR_R 		(mapped_r0)
					];
				} else {
					pr_err!("Incorrect BLR operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_BR => {
				// R
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					mapd_insn = assem![
						; BR_R 		(mapped_r0)
					];
				} else {
					pr_err!("Incorrect BR operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_CBNZ => {
				// RI
				// NOTE: this insn contains branching target in immediate number and has to be preserved across register mapping
				// Thus we use `disasm_one_preserve_addr()` instead of `disasm_no_addr()` to tackle this problem
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let offset = i0 - insn_addr as i64;
						mapd_insn = assem![
							; CBNZ_RI 		(mapped_r0, offset as u32)
						];
						reg_mapped_insn.push(disasm_one_preserve_addr(mapd_insn.as_ptr(), insn_addr).unwrap(), GFP_ATOMIC).unwrap();
					} else {
						pr_err!("Incorrect CBNZ operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_CBZ => {
				// RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let offset = i0 - insn_addr as i64;
						mapd_insn = assem![
							; CBZ_RI 		(mapped_r0, offset as u32)
						];
						reg_mapped_insn.push(disasm_one_preserve_addr(mapd_insn.as_ptr(), insn_addr).unwrap(), GFP_ATOMIC).unwrap();
					} else {
						pr_err!("Incorrect CBZ operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_CMN => {
				// RR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						mapd_insn = assem![
							; CMN_RR 		(mapped_r0, mapped_r1)
						];
					} else {
						pr_err!("Incorrect CMN operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect CMN operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_CMP => {
				// RR/RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					match get_operand(insn_ptr, 1) {
						Op::REG(r1) => {
							// CMP only access regs by READ, so we don't need to recover the mapped regs used in this insn
							let mapped_r1 = self.map_reg(Reg::from(r1));
							mapd_insn = assem![
								; CMP_RR 		(mapped_r0, mapped_r1)
							];
						}
						Op::IMM(i0) => {
							mapd_insn = assem![
								; CMP_RI 		(mapped_r0, i0 as u32)
							];
						}
						_ => {
							pr_err!("Incorrect CMP operand\n");
							self.status = false;
						}
					}
				}
			}
			Insn::ARM64_INS_CSET => {
				// RC
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					let cc = Cond::from(get_cc(insn_ptr));
					mapd_insn = assem![
						; CSET_RC 		(mapped_r0, cc)
					];
				} else {
					pr_err!("Incorrect CSET operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_EOR => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; EOR_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported EOR operand\n");
								self.status = false;
							}
						}
					} else {
						pr_err!("Incorrect EOR operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect EOR operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_LDP => {
				// RRM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						if let Op::MEM(r2, r3, i0) = get_operand(insn_ptr, 2) {
							let mapped_r2 = self.map_reg(Reg::from(r2));
							match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_LDP) {
								MemAccCls::PstIndex => {
									// Post index is in the extra IMM operand
									if let Op::IMM(i0) = get_operand(insn_ptr, 3) {
										mapd_insn = assem![
											; LDP_RRM 		(mapped_r0, mapped_r1, (mapped_r2, Reg::INV, i0 as u32, MemAccCls::PstIndex))
										];
									} else {
										pr_err!("Incorrect Post-Index operand\n");
									}
								}
								mem_acc => {
									// Post and Offset share the same logic
									mapd_insn = assem![
										; LDP_RRM 		(mapped_r0, mapped_r1, (mapped_r2, Reg::INV, i0 as u32, mem_acc))
									];
								}
							}
						} else {
							pr_err!("Unsupported LDP operand\n");
							self.status = false;
						}
					}
				}
			}
			Insn::ARM64_INS_LDR => {
				// RM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::MEM(r1, r2, i0) = get_operand(insn_ptr, 1) {
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_LDR) {
							MemAccCls::PstIndex => {
								if let Op::IMM(i0) = get_operand(insn_ptr, 2) {
									mapd_insn = assem![
										; LDR_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, MemAccCls::PstIndex))
									];
								} else {
									pr_err!("Incorrect Post-Index operand\n");
									self.status = false;
								}
							}
							mem_acc => {
								mapd_insn = assem![
									; LDR_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, mem_acc))
								];
							}
						}
					} else {
						pr_err!("Unsupported LDR operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_LDRB => {
				// RM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::MEM(r1, r2, i0) = get_operand(insn_ptr, 1) {
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_LDRB) {
							MemAccCls::PstIndex => {
								if let Op::IMM(i0) = get_operand(insn_ptr, 2) {
									mapd_insn = assem![
										; LDRB_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, MemAccCls::PstIndex))
									];
								} else {
									pr_err!("Incorrect Post-Index operand\n");
									self.status = false;
								}
							}
							mem_acc => {
								mapd_insn = assem![
									; LDRB_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, mem_acc))
								];
							}
						}
					} else {
						pr_err!("Unsupported LDRB operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_LDUR => {
				// RM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::MEM(r1, r2, i0) = get_operand(insn_ptr, 1) {
						let mapped_r1 = self.map_reg(Reg::from(r1));
						mapd_insn = assem![
							; LDUR_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, MemAccCls::Offset))
						];
					} else {
						pr_err!("Incorrect LDUR operand 1\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect LDUR operand 0\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_LSL => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; LSL_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported LSL operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_LSR => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; LSR_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported LSR operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_MOV => {
				// 2 possibilities: RR, RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					match get_operand(insn_ptr, 1) {
						Op::REG(r1) => {
							let mapped_r1 = self.map_reg(Reg::from(r1));
							mapd_insn = assem![
								; MOV_RR 		(mapped_r0, mapped_r1)
							];
						}
						Op::IMM(i0) => {
							mapd_insn = assem![
								; MOV_RI 		(mapped_r0, i0 as u32)
							];
						}
						_ => {
							pr_err!("Unsupported MOV operand\n");
							self.status = false;
						}
					}
				}
			}
			Insn::ARM64_INS_MOVK => {
				// RIF
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let (sft, val) = get_shift(insn_ptr, 1);
						let mut sft_cls = ShiftCls::from(sft);

						if sft_cls == ShiftCls::INV {
							sft_cls = ShiftCls::LSL;
						}
						
						mapd_insn = assem![
							; MOVK_RIF 		(mapped_r0, i0 as u32, (sft_cls, val))
						];
					} else {
						pr_err!("Incorrect MOVK operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect MOVK operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_MOVZ => {
				// RIF
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
						let (sft, val) = get_shift(insn_ptr, 1);
						let mut sft_cls = ShiftCls::from(sft);

						// ! TEST
						pr_info!("ConfReg: MOVZ {:?} {}\n", sft_cls, val);

						if sft_cls == ShiftCls::INV {
							sft_cls = ShiftCls::LSL;
						}

						mapd_insn = assem![
							; MOVZ_RIF 		(mapped_r0, i0 as u32, (sft_cls, val))
						];
					} else {
						pr_err!("Incorrect MOVZ operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect MOVZ operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_MRS => {
				pr_err!("In ARM64_INS_MRS\n");
				// RS
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::SYS(s0) = get_operand(insn_ptr, 1) {
						let s0 = SysReg::from(s0);
						// ! TEST
						pr_info!("{:?}\n,", s0);
						
						mapd_insn = assem![
							; MRS_RS 		(mapped_r0, s0)
						];
					} else {
						pr_err!("Incorrect MRS operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect MRS operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_MSR => {
				pr_err!("In ARM64_INS_MSR\n");
				// SR
				if let Op::SYS(s0) = get_operand(insn_ptr, 0) {
					let s0 = SysReg::from(s0);
					// ! TEST
					pr_info!("{:?}\n,", s0);

					if let Op::REG(r0) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						mapd_insn = assem![
							; MSR_SR 		(s0, mapped_r0)
						];
					} else {
						pr_err!("Incorrect MSR operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect MSR operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_MUL => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						if let Op::REG(r2) = get_operand(insn_ptr, 2) {
							let mapped_r2 = self.map_reg(Reg::from(r2));
							mapd_insn = assem![
								; MUL_RRR 		(mapped_r0, mapped_r1, mapped_r2)
							];
						} else {
							pr_err!("Incorrect MUL operand\n");
							self.status = false;
						}
					} else {
						pr_err!("Incorrect MUL operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect MUL operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_NEG => {
				// RR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						mapd_insn = assem![
							; NEG_RR 		(mapped_r0, mapped_r1)
						];
					} else {
						pr_err!("Incorrect NEG operand\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect NEG operand\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_ORR => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; ORR_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported ORR operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_ROR => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; ROR_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported ROR operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_STLXR => {
				// RRM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						if let Op::MEM(r2, _, _) = get_operand(insn_ptr, 2) {
							let mapped_r2 = self.map_reg(Reg::from(r2));
							mapd_insn = assem![
								; STLXR_RRM 	(mapped_r0, mapped_r1, (mapped_r2, Reg::INV, 0, MemAccCls::Offset))
							];
						} else {
							pr_err!("Unsupported STLXR operand 2\n");
							self.status = false;
						}
					} else {
						pr_err!("Unsupported STLXR operand 1\n");
						self.status = false;
					}
				} else {
					pr_err!("Unsupported STLXR operand 0\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_STP => {
				// RRM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						if let Op::MEM(r2, r3, i0) = get_operand(insn_ptr, 2) {
							let mapped_r2 = self.map_reg(Reg::from(r2));
							match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_STP) {
								MemAccCls::PstIndex => {
									if let Op::IMM(i0) = get_operand(insn_ptr, 3) {
										mapd_insn = assem![
											; STP_RRM 		(mapped_r0, mapped_r1, (mapped_r2, Reg::INV, i0 as u32, MemAccCls::PstIndex))
										];
									} else {
										pr_err!("Incorrect Post-Index operand\n");
										self.status = false;
									}
								}
								mem_acc => {
									mapd_insn = assem![
										; STP_RRM 		(mapped_r0, mapped_r1, (mapped_r2, Reg::INV, i0 as u32, mem_acc))
									];
								}
							}
						} else {
							pr_err!("Unsupported STP operand\n");
							self.status = false;
						}
					}
				}
			}
			Insn::ARM64_INS_STR => {
				// RM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::MEM(r1, r2, i0) = get_operand(insn_ptr, 1) {
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_STR) {
							MemAccCls::PstIndex => {
								if let Op::IMM(i0) = get_operand(insn_ptr, 2) {
									mapd_insn = assem![
										; STR_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, MemAccCls::PstIndex))
									];
								} else {
									pr_err!("Incorrect Post-Index operand\n");
									self.status = false;
								}
							}
							mem_acc => {
								let r2 = Reg::from(r2);
								match r2 {
									Reg::INV => {
										// STR (immediate)
										mapd_insn = assem![
											; STR_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, mem_acc))
										];
									}
									_ => {
										// STR (register)
										// ! TEST
										pr_info!("STP (register) reached\n");
										let mapped_r2 = self.map_reg(r2);
										mapd_insn = assem![
											; STR_RM 		(mapped_r0, (mapped_r1, mapped_r2, i0 as u32, mem_acc))
										];
									}
								}
							}
						}
					} else {
						pr_err!("Unsupported STR operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_STRB => {
				// RM
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::MEM(r1, r2, i0) = get_operand(insn_ptr, 1) {
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match check_mem_acc_cls(insn_bytes, Insn::ARM64_INS_STR) {
							MemAccCls::PstIndex => {
								if let Op::IMM(i0) = get_operand(insn_ptr, 2) {
									mapd_insn = assem![
										; STRB_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, MemAccCls::PstIndex))
									];
								} else {
									pr_err!("Incorrect Post-Index operand\n");
									self.status = false;
								}
							}
							mem_acc => {
								let r2 = Reg::from(r2);
								match r2 {
									Reg::INV => {
										// STRB (immediate)
										mapd_insn = assem![
											; STRB_RM 		(mapped_r0, (mapped_r1, Reg::INV, i0 as u32, mem_acc))
										];
									}
									_ => {
										// STRB (register)
										// ! TEST
										pr_err!("STRB (register) reached, unsupported\n");
										self.status = false;
									}
								}
							}
						}
					} else {
						pr_err!("Unsupported STRB operand\n");
						self.status = false;
					}
				}
			}
			Insn::ARM64_INS_STXR => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						if let Op::MEM(r2, r3, i0) = get_operand(insn_ptr, 2) {
							let mapped_r0 = self.map_reg(Reg::from(r0));
							let mapped_r1 = self.map_reg(Reg::from(r1));
							let mapped_r2 = self.map_reg(Reg::from(r2));
							mapd_insn = assem![
								; STXR_RRR 		(mapped_r0, mapped_r1, mapped_r2)
							];
						} else {
							pr_err!("Incorrect STXR operand 2\n");
							self.status = false;
						}
					} else {
						pr_err!("Incorrect STXR operand 1\n");
						self.status = false;
					}
				} else {
					pr_err!("Incorrect STXR operand 0\n");
					self.status = false;
				}
			}
			Insn::ARM64_INS_SUB => {
				// 2 possibilities: RRR/RRI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; SUB_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							Op::IMM(i0) => {
								mapd_insn = assem![
									; SUB_RRI 		(mapped_r0, mapped_r1, i0 as u32)
								];
							}
							_ => {
								pr_err!("Unsupported SUB operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_SUBS => {
				// RRR
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					if let Op::REG(r1) = get_operand(insn_ptr, 1) {
						let mapped_r0 = self.map_reg(Reg::from(r0));
						let mapped_r1 = self.map_reg(Reg::from(r1));
						match get_operand(insn_ptr, 2) {
							Op::REG(r2) => {
								let mapped_r2 = self.map_reg(Reg::from(r2));
								mapd_insn = assem![
									; SUBS_RRR 		(mapped_r0, mapped_r1, mapped_r2)
								];
							}
							_ => {
								pr_err!("Unsupported SUBS operand\n");
								self.status = false;
							}
						}
					}
				}
			}
			Insn::ARM64_INS_TST => {
				// RI
				if let Op::REG(r0) = get_operand(insn_ptr, 0) {
					let mapped_r0 = self.map_reg(Reg::from(r0));
					if let Op::IMM(i0) = get_operand(insn_ptr, 1) {
							mapd_insn = assem![
								; TST_RI 		(mapped_r0, i0 as u32)
							];
					} else {
						pr_err!("Unsupported TST operand\n");
						self.status = false;
					}
				}
			}
			// Other instructions
			insn_type => {
				// Unsupported instruction
				pr_err!("ConfRes - Unsupported insn: {:?}", insn_type);
				self.status = false;
			}
		}
		
		if !self.status {
			// Free prefix and suffix insns if we have failed to resolve
			// And we keep the original insn_ptr unfreed.
			free_insns(&prefix_insns);
			free_insns(&suffix_insns);
			Err(EFAULT)
		} else {
			utils::append(&mut reg_mapped_bytes, &mapd_insn).unwrap();
			// If we have not filled in reg_mapped_insn (i.e. not CBNZ/CBZ/TBNZ/TBZ)
			if reg_mapped_insn.is_empty() {
				// And we have no prefix insns
				if prefix_insns.is_empty() {
					utils::append(&mut reg_mapped_insn, &disasm_preserve_first_addr(mapd_insn.as_ptr(), mapd_insn.len(), insn_addr).unwrap()).unwrap();
				} else {
					utils::append(&mut reg_mapped_insn, &disasm_no_addr(mapd_insn.as_ptr(), mapd_insn.len()).unwrap()).unwrap();
				}
			}

			// Concat everything to prefix_*
			utils::append(&mut prefix_insns, &reg_mapped_insn).unwrap();
			utils::append(&mut prefix_insns, &suffix_insns).unwrap();
			utils::append(&mut prefix_bytes, &reg_mapped_bytes).unwrap();
			utils::append(&mut prefix_bytes, &suffix_bytes).unwrap();
			
			// If we ever fail in ConfResolver, we will not free those insns to avoid double free.
			self.insns_pending_free.push(insn_ptr, GFP_ATOMIC).unwrap();
			
			Ok((prefix_insns, prefix_bytes))
		}
	}

	/// Inserts necessary instructions to recover special registers at the end of each basic block.
	/// 
	/// Should be called only at the end of basic block preprocessing.
	pub(crate) fn recover(&mut self, insns: &mut Vec<*mut cs_insn>, bytes: &mut Vec<u8>) {
		// ! PENDING: We want to keep all consecutive insn with valid cc together
		// fx. cmp, ccmp, b.cc
		let mut backup_insns = Vec::new();
		let mut backup_bytes = Vec::new();

		if let Some(insn_ptr) = insns.pop() {
			// We first check the last insn
			match unsafe { Insn::from((*insn_ptr).id) } {
				Insn::ARM64_INS_B => {
					match Cond::from(get_cc(insn_ptr)) {
						Cond::AL | Cond::NV => {
							// If last insn is unconditional branching, check its previous instruction
							if let Some(prev_insn_ptr) = insns.pop() {
								match unsafe { Insn::from((*prev_insn_ptr).id) } {
									Insn::ARM64_INS_ADR => {
										// ADR is our translated result of SVC/BL/BLR/RET, we have to keep it with B,
										// so we pop the last 4 bytes and backs up `insn_ptr`, 
										// thus recovering insns can be inserted BEFORE inseparable insns.
										backup_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
										utils::append(&mut backup_bytes, &bytes[(bytes.len() - 4) .. bytes.len()]).unwrap();
										for _ in 0..4 {
											bytes.pop().unwrap();
										}
										// We have to put this instruction back!
										insns.push(prev_insn_ptr, GFP_ATOMIC).unwrap();
									}
									_ => {
										// Otherwise we just put back those insns because B's previous insn is not special
										insns.push(prev_insn_ptr, GFP_ATOMIC).unwrap();
										insns.push(insn_ptr, GFP_ATOMIC).unwrap();
									}
								}
							} else {
								// If no previous insn available, then this is a basic block with only one insn: B
								// We simply put that instruction back
								insns.push(insn_ptr, GFP_ATOMIC).unwrap();
							}
						}
						_ => {
							// If last insn is conditional branching, must prefixed with an insn that set the flags.
							// And that previous insn might also be conditional execution, so we keep looking up for consecutive conditional operations
							backup_insns.push(insn_ptr, GFP_ATOMIC).unwrap();
							utils::append(&mut backup_bytes, &bytes[(bytes.len() - 4) .. bytes.len()]).unwrap();
							for _ in 0..4 {
								bytes.pop().unwrap();
							}
							while let Some(prev_insn_ptr) = insns.pop() {
								match Cond::from(get_cc(prev_insn_ptr)) {
									Cond::AL | Cond::NV => {
										// No longer consecutive, restore insns can be inserted right before this insn.
										// We thus put back it and leave.
										insns.push(prev_insn_ptr, GFP_ATOMIC).unwrap();
										break;
									}
									_ => {
										// Otherwise it's still consecutive, we need to back insn and bytes up and continue traversing up.
										backup_insns.push(prev_insn_ptr, GFP_ATOMIC).unwrap();
										utils::append(&mut backup_bytes, &bytes[(bytes.len() - 4) .. bytes.len()]).unwrap();
										for _ in 0..4 {
											bytes.pop().unwrap();
										}
									}
								}
							}
						}
					}
				}
				_ => {
					// Other instructions doesn't matter, but we have to put back that insn_ptr
					insns.push(insn_ptr, GFP_ATOMIC).unwrap();
				}
			}

			// Recover our special reg reserve, we always insert the update_bytes before the last insn
			// ! PENDING: we only need to update regs that has seen WRITE operation in this basic block
			let reg_map_items = self.reg_map.items();
			for ii in 0..reg_map_items.len() {
				let (k, v) = reg_map_items[ii];
				if v != Reg::INV && !is_stable_reg(k) {
					let update_bytes = assem![
						; STR_RM 		(k, (Reg::SP, Reg::INV, self.reg_stack_map.find(v).unwrap(), MemAccCls::Offset))
					];
					// We have to insert before the last insn
					let bytes_len = bytes.len();
					utils::insert(bytes, &update_bytes, bytes_len - 4).unwrap();
					let insn_len = insns.len();
					utils::insert(insns, 
								  &disasm_no_addr(update_bytes.as_ptr(), update_bytes.len()).unwrap(),
								  insn_len - 1).unwrap();
				}
			}

			while let Some(ptr) = backup_insns.pop() {
				insns.push(ptr, GFP_ATOMIC).unwrap();
				utils::append(bytes, &backup_bytes[(backup_bytes.len() - 4) .. backup_bytes.len()]).unwrap();
				for _ in 0..4 {
					backup_bytes.pop().unwrap();
				}
			}
		}
	}
}
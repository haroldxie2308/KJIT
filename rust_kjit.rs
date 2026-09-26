// SPDX-License-Identifier: GPL-2.0

//! Kernel JIT implementation in Rust
//!
//! This kernel module provides a framework for userspace code JIT in kernel.
//! Init runs the K0 golden self-check, then starts the K2 runtime
//! (`runtime/`, `kjit_glue.c`).
#![allow(dead_code)]
#![allow(unused)]
#![allow(elided_lifetimes_in_paths)]

#[allow(missing_docs)]
pub mod shared;

mod runtime;

use kernel::prelude::*;

use shared::trans::input::{CodeProvider, CodeReadError, TranslationRequest, TranslationTrigger};
use shared::trans::translate::compile_request;

module! {
    type: RustKJIT,
    name: "rust_kjit",
    authors: ["WENHAO XIE"],
    description: "Rust KJIT Module",
    license: "GPL",
}

const KJIT_DEBUG: bool = true;

/// Harness reference output; see `harness/src/golden.rs` and `make kernel-golden`.
mod golden {
    include!("tests/arm64/golden/toy_cfg_hot_svc_mark.rs");
}

/// Serves the golden fixture's `.text` words as little-endian bytes.
struct GoldenCode;

impl CodeProvider for GoldenCode {
    fn entry_addr(&self) -> u64 {
        golden::GOLDEN_TEXT_BASE
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let unmapped = CodeReadError::Unmapped { pc, len: dst.len() };
        let relative = pc.checked_sub(golden::GOLDEN_TEXT_BASE).ok_or(unmapped)?;
        let start = usize::try_from(relative).map_err(|_| unmapped)?;
        let end = start.checked_add(dst.len()).ok_or(unmapped)?;
        if start % 4 != 0 || end > golden::GOLDEN_TEXT_WORDS.len() * 4 {
            return Err(unmapped);
        }
        for (index, byte) in dst.iter_mut().enumerate() {
            let at = start + index;
            *byte = golden::GOLDEN_TEXT_WORDS[at / 4].to_le_bytes()[at % 4];
        }
        Ok(())
    }
}

/// Translates the golden fixture in-kernel and compares the encoded fragment
/// byte-for-byte with the harness reference. The fragment is never executed.
fn check_golden() -> Result {
    let name = golden::GOLDEN_FIXTURE;
    let symbol = golden::GOLDEN_HOT_SVC_SYMBOL;
    let request = TranslationRequest {
        entry_pc: golden::GOLDEN_ENTRY_PC,
        trigger: TranslationTrigger::HotSvc,
        regs: None,
    };
    let fragment = match compile_request(&request, &GoldenCode) {
        Ok(fragment) => fragment,
        Err(err) => {
            // `pr_*!` only accepts `kernel::fmt::Display`; shared errors implement
            // `core::fmt::Display`, which `format_args!` bridges via `Arguments`.
            pr_err!(
                "golden {name}:{symbol} FAIL: compile_request: {}\n",
                format_args!("{err}")
            );
            return Err(EINVAL);
        }
    };

    let expected = &golden::GOLDEN_FRAGMENT_BYTES;
    let mut offset = 0usize;
    for insn in fragment.insns.iter() {
        let word = match insn.encode() {
            Ok(word) => word,
            Err(err) => {
                pr_err!("golden {name}:{symbol} FAIL: encode at offset {offset:#x}: {err:?}\n");
                return Err(EINVAL);
            }
        };
        for byte in word.to_le_bytes() {
            match expected.get(offset) {
                Some(&want) if want == byte => {}
                Some(&want) => {
                    pr_err!(
                        "golden {name}:{symbol} FAIL: first mismatch at offset {offset:#x}: expected {want:#04x}, got {byte:#04x}\n"
                    );
                    return Err(EINVAL);
                }
                None => {
                    pr_err!(
                        "golden {name}:{symbol} FAIL: fragment longer than golden ({} bytes), first extra byte at offset {offset:#x}\n",
                        expected.len()
                    );
                    return Err(EINVAL);
                }
            }
            offset += 1;
        }
    }
    if offset != expected.len() {
        pr_err!(
            "golden {name}:{symbol} FAIL: fragment is {offset} bytes, golden is {} bytes (first missing byte at offset {offset:#x})\n",
            expected.len()
        );
        return Err(EINVAL);
    }

    pr_info!("golden {name}:{symbol} PASS: {offset} fragment bytes match harness\n");
    Ok(())
}

struct RustKJIT {}

impl kernel::Module for RustKJIT {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("######## Rust KJIT inits ########\n");
        check_golden()?;
        runtime::init()?;
        Ok(RustKJIT {})
    }
}

impl Drop for RustKJIT {
    fn drop(&mut self) {
        runtime::exit();
        pr_info!("######## Rust KJIT exits ########\n");
    }
}

// SPDX-License-Identifier: GPL-2.0

//! Translation on request: the target's user text -> `compile_request` ->
//! encoded bytes -> `verify_fragment` -> install. Nothing is installed that the
//! verifier did not accept on exactly the bytes, fault-site table and entry
//! table that the C side installs.

use core::cell::RefCell;

use kernel::alloc::flags::GFP_KERNEL;
use kernel::error::code::{
    E2BIG, EAGAIN, EEXIST, EFAULT, EINVAL, ENODEV, ENOEXEC, ENOMEM, ENOSPC, EPERM,
};
use kernel::ffi::c_int;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;

use super::ffi::{self, KjitEntry, KjitMm, KjitSite};
use super::stats::{self, Stat};
use crate::shared::trans::cfg::{admit_at, UnsupportedExit};
use crate::shared::trans::input::{
    CodeProvider, CodeReadError, TranslationRequest, TranslationTrigger,
};
use crate::shared::trans::translate::compile_request;
use crate::shared::verify::{verify_fragment, FaultSiteEntry, VerifyInput, VerifyRule};

/// Distinct text pages one translation may read. `build_cfg` has no size bound
/// of its own (its block bookkeeping is quadratic), so the provider bounds it:
/// a fragment between two syscalls never needs 64 KiB of text.
const MAX_TEXT_PAGES: usize = 16;
/// `read_exact` calls per translation, for the same reason.
const MAX_TEXT_READS: usize = 16384;
/// Retries after an install lost a race with an mmu_notifier invalidation.
const MAX_RACE_RETRIES: usize = 3;

/// Why the text provider refused a read (the CFG only sees `Unmapped`).
#[derive(Clone, Copy, Debug)]
enum TextFault {
    /// `kjit_read_text_page` failed (errno): no VMA, or not executable and
    /// read-only.
    Denied(c_int),
    Budget,
    Alloc,
}

struct TextState {
    pages: KVec<(u64, KVec<u8>)>,
    reads: usize,
    /// Span of every byte handed to the translator: the fragment's source
    /// range for mmu_notifier invalidation.
    lo: u64,
    hi: u64,
    fault: Option<TextFault>,
}

/// `CodeProvider` over the target mm's text, one page snapshot per page.
struct UserText {
    kmm: *mut KjitMm,
    entry: u64,
    state: RefCell<TextState>,
}

impl UserText {
    fn new(kmm: *mut KjitMm, entry: u64) -> Self {
        Self {
            kmm,
            entry,
            state: RefCell::new(TextState {
                pages: KVec::new(),
                reads: 0,
                lo: u64::MAX,
                hi: 0,
                fault: None,
            }),
        }
    }
}

impl TextState {
    fn page(&mut self, kmm: *mut KjitMm, page: u64) -> Result<usize, TextFault> {
        if let Some(index) = self.pages.iter().position(|(addr, _)| *addr == page) {
            return Ok(index);
        }
        if self.pages.len() == MAX_TEXT_PAGES {
            return Err(TextFault::Budget);
        }
        let mut buf = KVec::from_elem(0u8, PAGE_SIZE, GFP_KERNEL).map_err(|_| TextFault::Alloc)?;
        // SAFETY: `kmm` is live for the translation (the caller holds a notifier
        // reference and mm_users); `buf` has PAGE_SIZE writable bytes.
        let rc = unsafe { ffi::kjit_read_text_page(kmm, page, buf.as_mut_ptr()) };
        if rc != 0 {
            return Err(TextFault::Denied(rc));
        }
        self.pages
            .push((page, buf), GFP_KERNEL)
            .map_err(|_| TextFault::Alloc)?;
        Ok(self.pages.len() - 1)
    }

    fn read(&mut self, kmm: *mut KjitMm, pc: u64, dst: &mut [u8]) -> Result<(), TextFault> {
        self.reads += 1;
        if self.reads > MAX_TEXT_READS {
            return Err(TextFault::Budget);
        }
        let page_mask = !(PAGE_SIZE as u64 - 1);
        for (i, byte) in dst.iter_mut().enumerate() {
            // A read that wraps past the top of the address space is unmapped.
            let addr = pc
                .checked_add(i as u64)
                .ok_or(TextFault::Denied(EFAULT.to_errno()))?;
            let page = addr & page_mask;
            let index = self.page(kmm, page)?;
            *byte = self.pages[index].1[(addr - page) as usize];
        }
        let end = pc.saturating_add(dst.len() as u64);
        self.lo = self.lo.min(pc);
        self.hi = self.hi.max(end);
        Ok(())
    }
}

impl CodeProvider for UserText {
    fn entry_addr(&self) -> u64 {
        self.entry
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let unmapped = CodeReadError::Unmapped { pc, len: dst.len() };
        // Not re-entrant: the translator never calls back into the provider
        // while a read runs, so the borrow cannot fail.
        let mut state = self.state.try_borrow_mut().map_err(|_| unmapped)?;
        state.read(self.kmm, pc, dst).map_err(|fault| {
            // Keep the first cause: the CFG may keep going after a failed read.
            if state.fault.is_none() {
                state.fault = Some(fault);
            }
            unmapped
        })
    }
}

/// Why a translation did not install; `errno` is what the debugfs write returns.
enum Failure {
    Text(TextFault),
    /// The entry instruction (this word) itself takes the Unsupported exit: the
    /// fragment could only return to userspace at its own entry, at the cost
    /// of a call.
    EntryUnsupported(u32),
    Compile,
    Encode,
    Verify(VerifyRule),
    /// The verifier reports `uses_fpsimd`, but this system has SVE or SME (or
    /// no FP/SIMD): not modelled, refused (docs/pipeline.md, "FP/SIMD in fragments (A9)").
    FpSimdUnsupportedCpu,
    Install(c_int),
    Alloc,
    Unaligned,
    Overflow,
}

impl Failure {
    fn errno(&self) -> c_int {
        match self {
            Failure::Text(TextFault::Denied(rc)) => *rc,
            Failure::Text(TextFault::Budget) => E2BIG.to_errno(),
            Failure::Text(TextFault::Alloc) | Failure::Alloc => ENOMEM.to_errno(),
            Failure::Compile | Failure::Encode | Failure::Unaligned | Failure::Overflow => {
                EINVAL.to_errno()
            }
            // Final for the auto mode's negative cache: the CPU does not change.
            Failure::FpSimdUnsupportedCpu => ENODEV.to_errno(),
            Failure::Verify(_) => EPERM.to_errno(),
            Failure::EntryUnsupported(_) => ENOEXEC.to_errno(),
            Failure::Install(rc) => *rc,
        }
    }
}

/// Translates the code at `pc` of `kmm`'s mm and installs it. Returns 0 or a
/// negative errno; -ENOEXEC (the entry instruction is not translatable) also
/// stores that word in `*entry_word` unless it is NULL. Every outcome is
/// counted; `verbose` logs failures (the single-PC `translate` file), verifier
/// rejections other than the known FallsOffEnd are always logged.
#[no_mangle]
extern "C" fn kjit_rs_translate(
    kmm: *mut KjitMm,
    pc: u64,
    verbose: bool,
    entry_word: *mut u32,
) -> c_int {
    let mut result = translate(kmm, pc, verbose);
    // Any invalidation of the mm while the text was read makes the install
    // fail, including ones on unrelated ranges (heap munmap in another
    // thread); a few retries make that rare without tracking ranges.
    for _ in 0..MAX_RACE_RETRIES {
        match result {
            Err(Failure::Install(rc)) if rc == EAGAIN.to_errno() => {
                stats::inc(Stat::TranslateRaced);
                result = translate(kmm, pc, verbose);
            }
            _ => break,
        }
    }
    match result {
        Ok(()) => {
            stats::inc(Stat::TranslateOk);
            0
        }
        Err(failure) => {
            let rc = failure.errno();
            match failure {
                Failure::Text(fault) => {
                    stats::inc(Stat::TranslateTextUnreadable);
                    if verbose {
                        pr_info!("kjit: pc {pc:#x}: text not translatable: {fault:?}\n");
                    }
                }
                Failure::EntryUnsupported(word) => {
                    stats::inc(Stat::TranslateEntryUnsupported);
                    if !entry_word.is_null() {
                        // SAFETY: the C caller passes a writable u32 or NULL.
                        unsafe { *entry_word = word };
                    }
                }
                Failure::Compile | Failure::Unaligned | Failure::Overflow => {
                    stats::inc(Stat::TranslateCompileFailed)
                }
                Failure::FpSimdUnsupportedCpu => stats::inc(Stat::FpsimdRefusedSveSme),
                Failure::Encode => stats::inc(Stat::TranslateEncodeFailed),
                Failure::Verify(VerifyRule::FallsOffEnd) => {
                    stats::inc(Stat::TranslateVerifyRejected);
                    stats::inc(Stat::TranslateVerifyFallsOffEnd);
                }
                Failure::Verify(_) => stats::inc(Stat::TranslateVerifyRejected),
                Failure::Install(_) if rc == EEXIST.to_errno() => {
                    stats::inc(Stat::TranslateExists)
                }
                Failure::Install(_) if rc == EAGAIN.to_errno() => {
                    stats::inc(Stat::TranslateRaced)
                }
                Failure::Install(_) if rc == ENOSPC.to_errno() => {
                    stats::inc(Stat::TranslateCapped)
                }
                Failure::Install(_) | Failure::Alloc => stats::inc(Stat::TranslateInstallFailed),
            }
            rc
        }
    }
}

fn translate(kmm: *mut KjitMm, pc: u64, verbose: bool) -> Result<(), Failure> {
    if pc % 4 != 0 {
        return Err(Failure::Unaligned);
    }
    // Before the first text read: an invalidation after this point makes the
    // install fail (kjit_install).
    // SAFETY: `kmm` is live for the call (see `TextState::page`).
    let seq = unsafe { ffi::kjit_mm_seq(kmm) };

    let text = UserText::new(kmm, pc);
    match admit_at(&text, pc) {
        Ok(Ok(_)) => {}
        Ok(Err(UnsupportedExit::Insn(insn))) => return Err(Failure::EntryUnsupported(insn.word)),
        // The entry is unreadable: the provider recorded why.
        Ok(Err(UnsupportedExit::Unreadable { .. })) => {
            let fault = text.state.borrow().fault;
            return Err(fault.map_or(Failure::Compile, Failure::Text));
        }
        Err(_) => return Err(Failure::Compile),
    }
    let request = TranslationRequest {
        entry_pc: pc,
        trigger: TranslationTrigger::Manual,
        regs: None,
    };
    let compiled = compile_request(&request, &text);
    let state = text.state.into_inner();
    let fragment = match compiled {
        Ok(fragment) => fragment,
        Err(err) => {
            if let Some(fault) = state.fault {
                return Err(Failure::Text(fault));
            }
            if verbose {
                pr_info!("kjit: pc {pc:#x}: compile_request: {}\n", format_args!("{err}"));
            }
            return Err(Failure::Compile);
        }
    };

    let mut code = KVec::with_capacity(fragment.len_bytes(), GFP_KERNEL).map_err(|_| Failure::Alloc)?;
    for insn in fragment.insns.iter() {
        let word = insn.encode().map_err(|err| {
            if verbose {
                pr_info!("kjit: pc {pc:#x}: encode: {err:?}\n");
            }
            Failure::Encode
        })?;
        code.extend_from_slice(&word.to_le_bytes(), GFP_KERNEL)
            .map_err(|_| Failure::Alloc)?;
    }

    // The verifier's tables are exactly what the kernel installs: the fault
    // sites become the extable, and the entry table is every offset the runtime
    // may pass as the entry address (entry_offset for `pc`, vlabels for
    // chaining inside the fragment).
    let mut sites = KVec::with_capacity(fragment.fault_sites.len(), GFP_KERNEL)
        .map_err(|_| Failure::Alloc)?;
    let mut ksites = KVec::with_capacity(fragment.fault_sites.len(), GFP_KERNEL)
        .map_err(|_| Failure::Alloc)?;
    for site in fragment.fault_sites.iter() {
        sites
            .push(
                FaultSiteEntry {
                    access_offset: site.access_offset,
                    stub_offset: site.stub_offset,
                },
                GFP_KERNEL,
            )
            .map_err(|_| Failure::Alloc)?;
        ksites
            .push(
                KjitSite {
                    access: u32::try_from(site.access_offset).map_err(|_| Failure::Overflow)?,
                    stub: u32::try_from(site.stub_offset).map_err(|_| Failure::Overflow)?,
                },
                GFP_KERNEL,
            )
            .map_err(|_| Failure::Alloc)?;
    }
    let mut entries = KVec::with_capacity(fragment.vlabels.len() + 1, GFP_KERNEL)
        .map_err(|_| Failure::Alloc)?;
    entries
        .push(fragment.entry_offset, GFP_KERNEL)
        .map_err(|_| Failure::Alloc)?;
    let mut kentries = KVec::with_capacity(fragment.vlabels.len(), GFP_KERNEL)
        .map_err(|_| Failure::Alloc)?;
    for &(label_pc, offset) in fragment.vlabels.iter() {
        entries.push(offset, GFP_KERNEL).map_err(|_| Failure::Alloc)?;
        let entry = KjitEntry {
            pc: label_pc,
            offset: u32::try_from(offset).map_err(|_| Failure::Overflow)?,
            pad: 0,
        };
        // Sorted by PC for the C side's binary search (vlabels hold each PC once).
        let at = kentries.partition_point(|e: &KjitEntry| e.pc < label_pc);
        kentries
            .insert_within_capacity(at, entry)
            .map_err(|_| Failure::Alloc)?;
    }

    let verified = match verify_fragment(&VerifyInput {
        code: &code,
        fault_sites: &sites,
        entry_offsets: &entries,
    }) {
        Ok(verified) => verified,
        Err(err) => {
            if verbose || err.rule != VerifyRule::FallsOffEnd {
                pr_warn!(
                    "kjit: pc {pc:#x}: verifier rejected the fragment at offset {:#x}: {:?}\n",
                    err.offset,
                    err.rule
                );
            }
            return Err(Failure::Verify(err.rule));
        }
    };
    // A fragment that touches the user's V registers or FPCR/FPSR runs only
    // inside the FP/SIMD bracket (kjit_call_fragment_fpsimd), selected by the
    // flag installed with it. The flag is the verifier's own `uses_fpsimd`,
    // derived from exactly the installed bytes, not the translator's view.
    // SAFETY: plain CPU capability query.
    if verified.uses_fpsimd && !unsafe { ffi::kjit_fpsimd_supported() } {
        if verbose {
            pr_info!("kjit: pc {pc:#x}: fragment uses FP/SIMD, refused on a CPU with SVE/SME\n");
        }
        return Err(Failure::FpSimdUnsupportedCpu);
    }

    let code_len = u32::try_from(code.len()).map_err(|_| Failure::Overflow)?;
    let entry_offset = u32::try_from(fragment.entry_offset).map_err(|_| Failure::Overflow)?;
    let n_sites = u32::try_from(ksites.len()).map_err(|_| Failure::Overflow)?;
    let n_entries = u32::try_from(kentries.len()).map_err(|_| Failure::Overflow)?;
    // SAFETY: `kmm` is live (see above); every pointer/length pair describes a
    // live KVec.
    let rc = unsafe {
        ffi::kjit_install(
            kmm,
            seq,
            pc,
            code.as_ptr(),
            code_len,
            entry_offset,
            ksites.as_ptr(),
            n_sites,
            kentries.as_ptr(),
            n_entries,
            state.lo,
            state.hi,
            verified.uses_fpsimd,
        )
    };
    if rc != 0 {
        if verbose {
            pr_info!("kjit: pc {pc:#x}: install failed: {rc}\n");
        }
        return Err(Failure::Install(rc));
    }
    if verbose {
        pr_info!(
            "kjit: pc {pc:#x}: installed {code_len} bytes, {n_sites} fault sites, {n_entries} entries, text {:#x}..{:#x}, fpsimd {}\n",
            state.lo,
            state.hi,
            verified.uses_fpsimd
        );
    }
    Ok(())
}

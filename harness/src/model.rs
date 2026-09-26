use std::collections::BTreeMap;
use std::fmt;

use crate::shared::arm64::{A64Reg, A64Reg31Mode};
use crate::shared::trans::cfg::RuntimeExitReason;

pub const PAGE_SIZE: u64 = 4096;

/// EL0 permission of a mapped user page. A page absent from the page map is
/// unmapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagePerm {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

/// Who performs a memory access. User accesses are checked against the user
/// page map; runtime accesses may only touch runtime-owned memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    User,
    Runtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemAccess {
    pub addr: u64,
    pub size: u8,
    pub kind: AccessKind,
}

/// A user access that violated page permissions (or was injected). The
/// faulting instruction did not retire: state is as before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemFault {
    pub pc: u64,
    pub access: MemAccess,
}

impl fmt::Display for MemFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.access.kind {
            AccessKind::Read => "read",
            AccessKind::Write => "write",
        };
        write!(
            f,
            "user {kind} fault pc={:#x} addr={:#x} size={}",
            self.pc, self.access.addr, self.access.size
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineState {
    regs: [u64; 31],
    sp: u64,
    pub flags: Flags,
    memory: BTreeMap<u64, u8>,
    /// User page map keyed by page base address.
    user_pages: BTreeMap<u64, PagePerm>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltReason {
    FellOffEnd,
    RuntimeExit { reason: RuntimeExitReason },
    Fault(MemFault),
}

impl fmt::Display for HaltReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HaltReason::Fault(fault) => write!(f, "Fault({fault})"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub state: MachineState,
    pub halt_reason: HaltReason,
    pub steps: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedState {
    pub regs: [u64; 31],
    pub sp: u64,
    pub flags: Flags,
    pub memory: BTreeMap<u64, u8>,
    pub halt_reason: HaltReason,
}

impl NormalizedState {
    pub fn from_execution(result: &ExecutionResult) -> Self {
        Self {
            regs: result.state.regs,
            sp: result.state.sp,
            flags: result.state.flags,
            memory: result.state.memory.clone(),
            halt_reason: result.halt_reason,
        }
    }
}

impl MachineState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sp(&self) -> u64 {
        self.sp
    }

    pub fn set_sp(&mut self, value: u64) {
        self.sp = value;
    }

    pub fn read_x(&self, reg: u8) -> u64 {
        assert!(reg <= 31, "invalid A64 register index: {reg}");
        if reg == 31 {
            0
        } else {
            self.regs[reg as usize]
        }
    }

    pub fn write_x(&mut self, reg: u8, value: u64) {
        assert!(reg <= 31, "invalid A64 register index: {reg}");
        if reg != 31 {
            self.regs[reg as usize] = value;
        }
    }

    pub fn read_reg(&self, reg: A64Reg) -> u64 {
        let enc = reg.enc();
        assert!(enc <= 31, "invalid A64 register index: {enc}");
        match (enc, reg.reg31) {
            (31, A64Reg31Mode::Sp) => self.sp,
            (31, _) => 0,
            _ => self.regs[enc as usize],
        }
    }

    pub fn write_reg(&mut self, reg: A64Reg, value: u64) {
        let enc = reg.enc();
        assert!(enc <= 31, "invalid A64 register index: {enc}");
        match (enc, reg.reg31) {
            (31, A64Reg31Mode::Sp) => self.sp = value,
            (31, _) => {}
            _ => self.regs[enc as usize] = value,
        }
    }

    pub fn read_xzr(&self, reg: A64Reg) -> u64 {
        let enc = reg.enc();
        assert!(enc <= 31, "invalid A64 register index: {enc}");
        if enc == 31 {
            0
        } else {
            self.regs[enc as usize]
        }
    }

    pub fn write_xzr(&mut self, reg: A64Reg, value: u64) {
        let enc = reg.enc();
        assert!(enc <= 31, "invalid A64 register index: {enc}");
        if enc != 31 {
            self.regs[enc as usize] = value;
        }
    }

    /// Maps every page of `[start, end)` with `perm`, replacing the permission
    /// of pages that are already mapped. Both bounds must be page-aligned.
    pub fn map_user_range(&mut self, start: u64, end: u64, perm: PagePerm) -> Result<(), String> {
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 || start >= end {
            return Err(format!(
                "user range {start:#x}..{end:#x} must be non-empty and {PAGE_SIZE:#x}-aligned"
            ));
        }
        for page in (start..end).step_by(PAGE_SIZE as usize) {
            self.user_pages.insert(page, perm);
        }
        Ok(())
    }

    pub fn user_page_perm(&self, addr: u64) -> Option<PagePerm> {
        self.user_pages.get(&page_base(addr)).copied()
    }

    /// Whether EL0 may perform `access`: every page it touches is mapped with
    /// a permission that allows it. An access that wraps the address space is
    /// never allowed.
    pub fn user_access_allowed(&self, access: MemAccess) -> bool {
        let Some(last) = access.addr.checked_add(access.size as u64 - 1) else {
            return false;
        };
        let mut page = page_base(access.addr);
        loop {
            let allowed = match (self.user_pages.get(&page), access.kind) {
                (None, _) => false,
                (Some(PagePerm::ReadOnly), AccessKind::Write) => false,
                (Some(_), _) => true,
            };
            if !allowed {
                return false;
            }
            if page == page_base(last) {
                return true;
            }
            page += PAGE_SIZE;
        }
    }

    /// Little-endian read of `size` bytes with no permission check. The
    /// interpreter validates an access before calling this; other callers are
    /// the runtime (its own memory) and tests.
    pub fn read_le(&self, addr: u64, size: u8) -> u64 {
        assert!(size <= 8, "memory read wider than 8 bytes: {size}");
        let mut bytes = [0_u8; 8];
        for (i, byte) in bytes.iter_mut().take(size as usize).enumerate() {
            // Storage elides zero bytes (see `write_le`), so an absent byte is a
            // stored zero. Validity of the address is the caller's check.
            *byte = self.memory.get(&(addr + i as u64)).copied().unwrap_or(0);
        }
        u64::from_le_bytes(bytes)
    }

    /// Little-endian write of the low `size` bytes of `value` with no
    /// permission check; see `read_le`.
    pub fn write_le(&mut self, addr: u64, size: u8, value: u64) {
        assert!(size <= 8, "memory write wider than 8 bytes: {size}");
        for (i, byte) in value
            .to_le_bytes()
            .into_iter()
            .take(size as usize)
            .enumerate()
        {
            if byte == 0 {
                self.memory.remove(&(addr + i as u64));
            } else {
                self.memory.insert(addr + i as u64, byte);
            }
        }
    }

    pub fn read_u64(&self, addr: u64) -> u64 {
        self.read_le(addr, 8)
    }

    pub fn write_u64(&mut self, addr: u64, value: u64) {
        self.write_le(addr, 8, value);
    }

    pub fn seed_memory_u64(&mut self, addr: u64, value: u64) {
        self.write_u64(addr, value);
    }

    pub fn memory(&self) -> &BTreeMap<u64, u8> {
        &self.memory
    }

    pub fn without_memory_ranges(&self, ranges: &[(u64, u64)]) -> Self {
        let mut cloned = self.clone();
        cloned.memory.retain(|addr, _| {
            !ranges
                .iter()
                .any(|(start, end)| *start <= *addr && *addr < *end)
        });
        cloned
    }

    pub fn update_sub_flags(&mut self, lhs: u64, rhs: u64, result: u64) {
        self.flags.n = (result >> 63) != 0;
        self.flags.z = result == 0;
        self.flags.c = lhs >= rhs;
        self.flags.v = ((lhs ^ rhs) & (lhs ^ result) & (1_u64 << 63)) != 0;
    }
}

fn page_base(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

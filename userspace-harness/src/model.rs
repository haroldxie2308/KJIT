use std::collections::BTreeMap;

use crate::trans_core::cfg::RuntimeExitReason;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MachineState {
    regs: [u64; 32],
    pub flags: Flags,
    memory: BTreeMap<u64, u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaltReason {
    FellOffEnd,
    StepLimitExceeded,
    RuntimeExit { reason: RuntimeExitReason },
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
    pub flags: Flags,
    pub memory: BTreeMap<u64, u8>,
    pub halt_reason: HaltReason,
}

impl NormalizedState {
    pub fn from_execution(result: &ExecutionResult) -> Self {
        let mut regs = [0_u64; 31];
        regs.copy_from_slice(&result.state.regs[..31]);
        Self {
            regs,
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

    pub fn read_reg(&self, reg: u8) -> u64 {
        if reg == 31 {
            0
        } else {
            self.regs[reg as usize]
        }
    }

    pub fn write_reg(&mut self, reg: u8, value: u64) {
        if reg != 31 {
            self.regs[reg as usize] = value;
        }
    }

    pub fn read_u64(&self, addr: u64) -> u64 {
        let mut bytes = [0_u8; 8];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = *self.memory.get(&(addr + i as u64)).unwrap_or(&0);
        }
        u64::from_le_bytes(bytes)
    }

    pub fn write_u64(&mut self, addr: u64, value: u64) {
        for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
            if byte == 0 {
                self.memory.remove(&(addr + i as u64));
            } else {
                self.memory.insert(addr + i as u64, byte);
            }
        }
    }

    pub fn seed_memory_u64(&mut self, addr: u64, value: u64) {
        self.write_u64(addr, value);
    }

    pub fn update_sub_flags(&mut self, lhs: u64, rhs: u64, result: u64) {
        self.flags.n = (result >> 63) != 0;
        self.flags.z = result == 0;
        self.flags.c = lhs >= rhs;
        self.flags.v = ((lhs ^ rhs) & (lhs ^ result) & (1_u64 << 63)) != 0;
    }
}

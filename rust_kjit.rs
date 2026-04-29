// SPDX-License-Identifier: GPL-2.0

//! Kernel JIT implementation in Rust
//! 
//! This kernel module provides a framework for userspace code JIT in kernel.
#![allow(dead_code)]
#![allow(unused)]
#![allow(elided_lifetimes_in_paths)]

#[allow(missing_docs)]
#[path = "shared/trans_core/mod.rs"]
pub mod trans_core;

use kernel::prelude::*;

module! {
    type: RustKJIT,
    name: "rust_kjit",
    authors: ["WENHAO XIE"],
    description: "Rust KJIT Module",
    license: "GPL",
}

const KJIT_DEBUG: bool = true;

struct RustKJIT {}

impl kernel::Module for RustKJIT {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("######## Rust KJIT inits ########\n");
        Ok(RustKJIT {})
    }
}

impl Drop for RustKJIT {
    fn drop(&mut self) {
        pr_info!("######## Rust KJIT exits ########\n");
    }
}

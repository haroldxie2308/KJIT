// SPDX-License-Identifier: GPL-2.0

//! Kernel JIT implementation in Rust
//! 
//! This kernel module provides a framework for userspace code JIT in kernel.
#![allow(dead_code)]
#![allow(unused)]
#![allow(elided_lifetimes_in_paths)]

use kernel::prelude::*;

mod trans;
mod utils;
mod uca;

module! {
    type: RustKJIT,
    name: "rust_kjit",
    author: "WENHAO XIE",
    description: "Rust KJIT Module",
    license: "GPL",
}

const KJIT_DEBUG: bool = true;

struct RustKJIT {}

impl kernel::Module for RustKJIT {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("######## Rust KJIT inits ########\n");
        trans::up();
    	uca::up();
        Ok(RustKJIT {})
    }
}

impl Drop for RustKJIT {
    fn drop(&mut self) {
    	uca::down();
        trans::down();
        pr_info!("######## Rust KJIT exits ########\n");
    }
}

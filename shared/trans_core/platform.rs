//! Shared platform boundary.
//!
//! Keep this module small. It is the place for compatibility types that are
//! valid in both the userspace harness and the kernel module.

pub type SharedResult<T, E> = core::result::Result<T, E>;

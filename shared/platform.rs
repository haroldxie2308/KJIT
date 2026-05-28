//! Shared platform boundary.
//!
//! Keep this module small. It is the place for compatibility types that are
//! valid in both the harness and the kernel module.

use core::ops::{Deref, DerefMut};

#[cfg(not(CONFIG_RUST))]
use alloc::vec::Vec as PlatformVec;

#[cfg(CONFIG_RUST)]
use kernel::alloc::KVec as PlatformVec;

#[cfg(CONFIG_RUST)]
pub use kernel::alloc::flags::GFP_KERNEL;

pub type SharedResult<T, E> = core::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedAllocError {
    Alloc,
    InvalidIndex,
}

#[cfg(not(CONFIG_RUST))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocFlags;

#[cfg(CONFIG_RUST)]
pub type AllocFlags = kernel::alloc::Flags;

#[cfg(not(CONFIG_RUST))]
pub const GFP_KERNEL: AllocFlags = AllocFlags;

#[derive(Default)]
pub struct SharedVec<T> {
    inner: PlatformVec<T>,
}

impl<T> SharedVec<T> {
    pub const fn new() -> Self {
        Self {
            inner: PlatformVec::new(),
        }
    }

    pub fn with_capacity(
        capacity: usize,
        flags: AllocFlags,
    ) -> SharedResult<Self, SharedAllocError> {
        Ok(Self {
            inner: platform_vec_with_capacity(capacity, flags)?,
        })
    }

    pub fn push(&mut self, value: T, flags: AllocFlags) -> SharedResult<(), SharedAllocError> {
        platform_vec_push(&mut self.inner, value, flags)
    }

    pub fn insert(
        &mut self,
        index: usize,
        value: T,
        flags: AllocFlags,
    ) -> SharedResult<(), SharedAllocError> {
        platform_vec_insert(&mut self.inner, index, value, flags)
    }

    pub fn append(&mut self, other: Self, flags: AllocFlags) -> SharedResult<(), SharedAllocError> {
        platform_vec_append(&mut self.inner, other.inner, flags)
    }

    pub fn split_off_copy(
        &mut self,
        at: usize,
        flags: AllocFlags,
    ) -> SharedResult<Self, SharedAllocError>
    where
        T: Copy,
    {
        if at > self.len() {
            return Err(SharedAllocError::InvalidIndex);
        }

        let mut tail = Self::with_capacity(self.len() - at, flags)?;
        for item in &self[at..] {
            tail.push(*item, flags)?;
        }
        platform_vec_truncate(&mut self.inner, at);
        Ok(tail)
    }
}

impl<T> Deref for SharedVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for SharedVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for SharedVec<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T: PartialEq> PartialEq for SharedVec<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Eq> Eq for SharedVec<T> {}

impl<'a, T> IntoIterator for &'a SharedVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut SharedVec<T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[cfg(not(CONFIG_RUST))]
fn platform_vec_with_capacity<T>(
    capacity: usize,
    _flags: AllocFlags,
) -> SharedResult<PlatformVec<T>, SharedAllocError> {
    Ok(PlatformVec::with_capacity(capacity))
}

#[cfg(CONFIG_RUST)]
fn platform_vec_with_capacity<T>(
    capacity: usize,
    flags: AllocFlags,
) -> SharedResult<PlatformVec<T>, SharedAllocError> {
    PlatformVec::with_capacity(capacity, flags).map_err(|_| SharedAllocError::Alloc)
}

#[cfg(not(CONFIG_RUST))]
fn platform_vec_push<T>(
    vec: &mut PlatformVec<T>,
    value: T,
    _flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    vec.push(value);
    Ok(())
}

#[cfg(CONFIG_RUST)]
fn platform_vec_push<T>(
    vec: &mut PlatformVec<T>,
    value: T,
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    vec.push(value, flags).map_err(|_| SharedAllocError::Alloc)
}

#[cfg(not(CONFIG_RUST))]
fn platform_vec_insert<T>(
    vec: &mut PlatformVec<T>,
    index: usize,
    value: T,
    _flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    if index > vec.len() {
        return Err(SharedAllocError::InvalidIndex);
    }
    vec.insert(index, value);
    Ok(())
}

#[cfg(CONFIG_RUST)]
fn platform_vec_insert<T>(
    vec: &mut PlatformVec<T>,
    index: usize,
    value: T,
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    vec.reserve(1, flags).map_err(|_| SharedAllocError::Alloc)?;
    vec.insert_within_capacity(index, value)
        .map_err(|_| SharedAllocError::InvalidIndex)
}

#[cfg(not(CONFIG_RUST))]
fn platform_vec_append<T>(
    vec: &mut PlatformVec<T>,
    mut other: PlatformVec<T>,
    _flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    vec.append(&mut other);
    Ok(())
}

#[cfg(CONFIG_RUST)]
fn platform_vec_append<T>(
    vec: &mut PlatformVec<T>,
    other: PlatformVec<T>,
    flags: AllocFlags,
) -> SharedResult<(), SharedAllocError> {
    for item in other {
        vec.push(item, flags).map_err(|_| SharedAllocError::Alloc)?;
    }
    Ok(())
}

#[cfg(not(CONFIG_RUST))]
fn platform_vec_truncate<T>(vec: &mut PlatformVec<T>, len: usize) {
    vec.truncate(len);
}

#[cfg(CONFIG_RUST)]
fn platform_vec_truncate<T>(vec: &mut PlatformVec<T>, len: usize) {
    vec.truncate(len);
}

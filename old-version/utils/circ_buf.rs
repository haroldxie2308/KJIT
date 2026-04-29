use kernel::prelude::*;
use kernel::alloc::Flags;
use alloc::fmt::{Formatter, Debug};

pub(crate) mod prelude {
    pub(crate) use super::{CircBuf, CircBufError};
}

/// A circular buffer that support enque and deque operations
pub(crate) struct CircBuf<T: Clone + Copy + Default> {
	buf: Vec<T>,
	// Begin and end always point to empty slot when methods exit
	begin: usize,
	end: usize,
	capacity: usize,
}

impl Debug for CircBuf<u64> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "[ ")?;
        if self.begin < self.end {
            for i in (self.begin + 1)..self.end {
                write!(f, "{:#x?}, ", self.buf[i])?;
            }
        } else {
            for i in (self.begin + 1)..self.capacity {
                write!(f, "{:#x?}, ", self.buf[i])?;
            }
            for i in 0..self.end {
                write!(f, "{:#x?}, ", self.buf[i])?;
            }
        }
        write!(f, "]\n")?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum CircBufError {
	OutOfCapacity,
	OutOfElem,
	OutOfMem,
}

impl<T: Clone + Copy + Default> CircBuf<T> {
	/// Can only store `capacity - 1` elements in the buffer for ease of implementation
    pub(crate) fn with_capacity(capacity: usize, flags: Flags) -> Result<Self, CircBufError> {
    	match Vec::with_capacity(capacity, flags) {
    		Ok(mut buf) => {
    			// # Several Considerations
    			// 
    			// If we set the len to be capacity, when droppîng the value we might get into trouble.
    			// By not setting the length, however, we might leak memory and we can't access element directly by subscripting.
    			// We choose to set our len here and unset it in our own implementation of the Drop trait.
    			unsafe { buf.set_len(capacity); }
    			Ok(Self {
    				buf,
    				begin: 0,
    				end: 1,
    				capacity,
    			})
    		}
    		Err(_) => {
    			Err(CircBufError::OutOfMem)
    		}
    	}
    }

    pub(crate) fn capacity(&self) -> usize {
    	self.capacity
    }

    pub(crate) fn is_empty(&self) -> bool {
    	(self.begin + 1) % self.capacity == self.end
    }

    pub(crate) fn is_full(&self) -> bool {
    	self.end == self.begin
    }

    pub(crate) fn enque(&mut self, elem: T) -> Result<(), CircBufError> {
    	if self.is_full() {
    		Err(CircBufError::OutOfCapacity)
    	} else {
    		self.buf[self.end] = elem;
    		self.end = (self.end + 1) % self.capacity;
    		Ok(())
    	}
    }

    /// Gets the element at the front
    pub(crate) fn deque(&mut self) -> Result<T, CircBufError> {
    	if self.is_empty() {
    		Err(CircBufError::OutOfElem)
    	} else {
    		self.begin = (self.begin + 1) % self.capacity;
    		let elem = self.buf[self.begin];
    		self.buf[self.begin] = T::default();
    		Ok(elem)
    	}
    }

    // Same as enque, push element to the end
    pub(crate) fn push(&mut self, elem: T) -> Result<(), CircBufError> {
    	self.enque(elem)
    }

    /// Gets the element at the end
    pub(crate) fn pop(&mut self) -> Result<T, CircBufError> {
    	if self.is_empty() {
    		Err(CircBufError::OutOfElem)
    	} else {
    		self.end = if self.end != 0 { self.end - 1 } else { self.capacity - 1 };
    		let elem = self.buf[self.end];
    		self.buf[self.end] = T::default();
    		Ok(elem)
    	}
    }
}

impl<T: Clone + Copy + Default> Drop for CircBuf<T> {
	fn drop(&mut self) {
		while (self.begin + 1) % self.capacity != self.end {
    		self.end = if self.end != 0 { self.end - 1 } else { self.capacity - 1 };
    		self.buf[self.end] = T::default();
		}
	    unsafe { self.buf.set_len(0); }
	}
}
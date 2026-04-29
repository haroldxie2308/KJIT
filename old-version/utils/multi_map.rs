pub(crate) mod prelude {
	pub(crate) use super::MultiMap;
}

use kernel::prelude::*;
use alloc::fmt::Debug;

#[derive(Debug, Default)]
pub(crate) struct MultiMap<K, V> {
	values: Vec<(K, V)>,
}

impl<K: Clone + Copy + Debug + Eq, V: Clone + Copy + Debug> core::ops::Index<K> for MultiMap<K, V> {
	type Output = V;
	fn index(&self, index: K) -> &Self::Output {
		for i in 0..self.values.len() {
			let (k, _) = self.values[i];
			if index == k {
				return &self.values[i].1;
			}
		}
		panic!("MultiMap indexing out-of-range");
	}
}

impl<K: Clone + Copy + Debug + Eq, V: Clone + Copy + Debug> core::ops::IndexMut<K> for MultiMap<K, V> {
	fn index_mut(&mut self, index: K) -> &mut V {
		for i in 0..self.values.len() {
			let (k, _) = self.values[i];
			if index == k {
				return &mut self.values[i].1;
			}
		}
		panic!("MultiMap indexing out-of-range");
	}
}

impl<K: Clone + Copy + Debug + Eq, V: Clone + Copy + Debug> MultiMap<K, V> {
	pub(crate) fn new() -> Self {
		Self { values: Vec::new(), }
	}

	pub(crate) fn insert(&mut self, key: K, value: V) -> Result<(), kernel::alloc::AllocError> {
		self.values.push((key, value), GFP_ATOMIC)
	}

	pub(crate) fn len(&self) -> usize {
		self.values.len()
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.values.is_empty()
	}

	/// Retrieves the value associated with `key`
	pub(crate) fn find(&self, key: K) -> Option<V> {
		for i in 0..self.values.len() {
			let (k, val) = self.values[i];
			if key == k {
				return Some(val);
			}
		}
		None
	}

	/// Retrieves all values associated with this key
	pub(crate) fn find_all(&self, key: K) -> Result<Vec<V>, kernel::alloc::AllocError> {
		let mut ret = Vec::new();
		for i in 0..self.values.len() {
			let (k, val) = self.values[i];
			if key == k {
				ret.push(val, GFP_ATOMIC)?;
			}
		}
		Ok(ret)
	}

	/// Searches for the first key whose value satisfies some predicate
	pub(crate) fn search(&self, pred: impl Fn(V) -> bool) -> Option<K> {
		for i in 0..self.values.len() {
			let (key, val) = self.values[i];
			if pred(val) {
				return Some(key);
			}
		}
		return None;
	}

	/// Searches for keys whose value satisfies some predicate
	pub(crate) fn search_all(&self, pred: impl Fn(V) -> bool) -> Result<Vec<K>, kernel::alloc::AllocError> {
		let mut ret = Vec::new();
		for i in 0..self.values.len() {
			let (key, val) = self.values[i];
			if pred(val) {
				ret.push(key, GFP_ATOMIC)?;
			}
		}
		Ok(ret)
	}

	/// Inverses the Map
	pub(crate) fn inverse(&self) -> Result<MultiMap<V, K>, kernel::alloc::AllocError>
	where V: Eq {
		let mut inv = MultiMap::new();
		for i in 0..self.values.len() {
			let (key, val) = self.values[i];
			inv.insert(val, key)?;
		}
		Ok(inv)
	}

	/// Finds the first key associated with this value
	pub(crate) fn find_val(&self, val: V) -> Option<K> 
	where V: Eq {
		for i in 0..self.values.len() {
			let (key, v) = self.values[i];
			if val == v {
				return Some(key);
			}
		}
		return None;
	}

	/// Finds all keys associated with this value
	pub(crate) fn find_val_all(&self, val: V) -> Result<Vec<K>, kernel::alloc::AllocError>
	where V: Eq {
		let mut ret = Vec::new();
		for i in 0..self.values.len() {
			let (key, v) = self.values[i];
			if val == v {
				ret.push(key, GFP_ATOMIC)?;
			}
		}
		Ok(ret)
	}

	pub(crate) fn items(&self) -> &Vec<(K, V)> {
		&self.values
	}

	pub(crate) fn items_mut(&mut self) -> &mut Vec<(K, V)> {
		&mut self.values
	}
}
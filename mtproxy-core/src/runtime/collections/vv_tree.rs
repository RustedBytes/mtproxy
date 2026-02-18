//! Safe collection types that back legacy `vv_tree` behavior.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Pointer-key map replacement for simple `vv_tree` usages.
#[derive(Clone, Debug, Default)]
pub struct VvTreeMap {
    values: BTreeMap<usize, i32>,
}

impl VvTreeMap {
    /// Inserts one key/priority pair when absent.
    pub fn insert_if_absent(&mut self, key: usize, priority: i32) {
        let _ = self.values.entry(key).or_insert(priority);
    }

    /// Returns whether the key exists.
    #[must_use]
    pub fn contains(&self, key: usize) -> bool {
        self.values.contains_key(&key)
    }

    /// Removes one key.
    pub fn remove(&mut self, key: usize) -> bool {
        self.values.remove(&key).is_some()
    }

    /// Clears all keys.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Returns current key count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true when no keys are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns keys in stable sorted order.
    #[must_use]
    pub fn keys_sorted(&self) -> Vec<usize> {
        self.values.keys().copied().collect()
    }
}

/// Safe set-based model for connection tree operations.
#[derive(Clone, Debug, Default)]
pub struct ConnectionTree {
    values: BTreeSet<usize>,
}

impl ConnectionTree {
    /// Inserts one connection pointer value.
    pub fn insert(&mut self, conn: usize) {
        let _ = self.values.insert(conn);
    }

    /// Removes one connection pointer value.
    ///
    /// Returns `true` when the tree is empty after removal.
    #[must_use]
    pub fn remove_and_is_empty(&mut self, conn: usize) -> bool {
        let _ = self.values.remove(&conn);
        self.values.is_empty()
    }

    /// Checks whether the connection exists.
    #[must_use]
    pub fn contains(&self, conn: usize) -> bool {
        self.values.contains(&conn)
    }

    /// Returns values in stable sorted order.
    #[must_use]
    pub fn values_sorted(&self) -> Vec<usize> {
        self.values.iter().copied().collect()
    }
}

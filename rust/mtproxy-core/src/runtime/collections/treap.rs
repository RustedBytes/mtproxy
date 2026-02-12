//! Treap (Randomized Binary Search Tree) implementation.
//!
//! This module provides a Rust implementation of the treap data structure
//! that replaces the C implementation in `vv/vv-tree.c`.
//!
//! A treap is a binary search tree that maintains both:
//! - BST property on keys (X values)
//! - Heap property on priorities (Y values)
//!
//! This ensures O(log n) expected time for operations while being simpler
//! than balanced trees like AVL or Red-Black trees.

use core::cmp::Ordering;
use core::fmt::Debug;
use alloc::boxed::Box;
use alloc::sync::Arc;

/// A node in the treap.
struct TreapNode<K, P> {
    key: K,
    priority: P,
    left: Option<Box<TreapNode<K, P>>>,
    right: Option<Box<TreapNode<K, P>>>,
}

impl<K, P> TreapNode<K, P> {
    /// Creates a new treap node with the given key and priority.
    const fn new(key: K, priority: P) -> Self {
        Self {
            key,
            priority,
            left: None,
            right: None,
        }
    }
}

/// A treap data structure.
///
/// # Type Parameters
/// - `K`: Key type (must implement `Ord`)
/// - `P`: Priority type (must implement `Ord`)
pub struct Treap<K, P> {
    root: Option<Box<TreapNode<K, P>>>,
    count: usize,
}

impl<K, P> Default for Treap<K, P>
where
    K: Ord,
    P: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, P> Treap<K, P>
where
    K: Ord,
    P: Ord,
{
    /// Creates a new empty treap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: None,
            count: 0,
        }
    }

    /// Returns the number of elements in the treap.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the treap is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Inserts a key-value pair into the treap.
    ///
    /// If the key already exists, this operation has no effect.
    pub fn insert(&mut self, key: K, priority: P) {
        let (left, right) = Self::split(self.root.take(), &key);
        let new_node = Box::new(TreapNode::new(key, priority));
        self.root = Some(Self::merge_three(left, new_node, right));
        self.count += 1;
    }

    /// Looks up a key in the treap and returns a reference to it if found.
    #[must_use]
    pub fn lookup(&self, key: &K) -> Option<&K> {
        let mut current = self.root.as_ref()?;

        loop {
            match key.cmp(&current.key) {
                Ordering::Equal => return Some(&current.key),
                Ordering::Less => current = current.left.as_ref()?,
                Ordering::Greater => current = current.right.as_ref()?,
            }
        }
    }

    /// Deletes a key from the treap.
    ///
    /// Returns `true` if the key was found and deleted, `false` otherwise.
    pub fn delete(&mut self, key: &K) -> bool {
        let (found, new_root) = Self::delete_internal(self.root.take(), key);
        self.root = new_root;
        if found {
            self.count -= 1;
        }
        found
    }

    /// Clears the treap, removing all elements.
    pub fn clear(&mut self) {
        self.root = None;
        self.count = 0;
    }

    /// Internal delete operation that returns whether the key was found
    /// and the new subtree.
    fn delete_internal(
        node: Option<Box<TreapNode<K, P>>>,
        key: &K,
    ) -> (bool, Option<Box<TreapNode<K, P>>>) {
        let mut node = match node {
            Some(n) => n,
            None => return (false, None),
        };

        match key.cmp(&node.key) {
            Ordering::Equal => {
                let merged = Self::merge(node.left.take(), node.right.take());
                (true, merged)
            }
            Ordering::Less => {
                let (found, new_left) = Self::delete_internal(node.left.take(), key);
                node.left = new_left;
                (found, Some(node))
            }
            Ordering::Greater => {
                let (found, new_right) = Self::delete_internal(node.right.take(), key);
                node.right = new_right;
                (found, Some(node))
            }
        }
    }

    /// Splits a treap into two parts around a key.
    ///
    /// Returns `(left, right)` where:
    /// - `left` contains all keys < `key`
    /// - `right` contains all keys >= `key`
    fn split(
        node: Option<Box<TreapNode<K, P>>>,
        key: &K,
    ) -> (Option<Box<TreapNode<K, P>>>, Option<Box<TreapNode<K, P>>>) {
        let mut node = match node {
            Some(n) => n,
            None => return (None, None),
        };

        if key <= &node.key {
            let (left, right) = Self::split(node.left.take(), key);
            node.left = right;
            (left, Some(node))
        } else {
            let (left, right) = Self::split(node.right.take(), key);
            node.right = left;
            (Some(node), right)
        }
    }

    /// Merges two treaps.
    ///
    /// Assumes all keys in `left` are less than all keys in `right`.
    fn merge(
        left: Option<Box<TreapNode<K, P>>>,
        right: Option<Box<TreapNode<K, P>>>,
    ) -> Option<Box<TreapNode<K, P>>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (Some(mut left), Some(mut right)) => {
                if left.priority > right.priority {
                    left.right = Self::merge(left.right.take(), Some(right));
                    Some(left)
                } else {
                    right.left = Self::merge(Some(left), right.left.take());
                    Some(right)
                }
            }
        }
    }

    /// Merges three parts: left, middle (single node), and right.
    fn merge_three(
        left: Option<Box<TreapNode<K, P>>>,
        mut middle: Box<TreapNode<K, P>>,
        right: Option<Box<TreapNode<K, P>>>,
    ) -> Box<TreapNode<K, P>> {
        middle.left = left;
        middle.right = right;
        middle
    }

    /// Performs an in-order traversal of the treap, calling `f` for each key.
    pub fn traverse<F>(&self, mut f: F)
    where
        F: FnMut(&K),
    {
        Self::traverse_internal(self.root.as_ref(), &mut f);
    }

    /// Internal traversal helper.
    fn traverse_internal<F>(node: Option<&Box<TreapNode<K, P>>>, f: &mut F)
    where
        F: FnMut(&K),
    {
        if let Some(node) = node {
            Self::traverse_internal(node.left.as_ref(), f);
            f(&node.key);
            Self::traverse_internal(node.right.as_ref(), f);
        }
    }
}

impl<K: Debug, P: Debug> Debug for Treap<K, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Treap")
            .field("count", &self.count)
            .finish()
    }
}

/// Thread-safe wrapper around a treap using `Arc` and interior mutability.
pub struct ThreadSafeTreap<K, P> {
    inner: Arc<parking_lot::RwLock<Treap<K, P>>>,
}

impl<K, P> Clone for ThreadSafeTreap<K, P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K, P> Default for ThreadSafeTreap<K, P>
where
    K: Ord,
    P: Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, P> ThreadSafeTreap<K, P>
where
    K: Ord,
    P: Ord,
{
    /// Creates a new thread-safe treap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(Treap::new())),
        }
    }

    /// Returns the number of elements in the treap.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` if the treap is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Inserts a key-value pair into the treap.
    pub fn insert(&self, key: K, priority: P) {
        self.inner.write().insert(key, priority);
    }

    /// Looks up a key in the treap.
    pub fn lookup<F, R>(&self, key: &K, f: F) -> Option<R>
    where
        F: FnOnce(&K) -> R,
    {
        let treap = self.inner.read();
        treap.lookup(key).map(f)
    }

    /// Deletes a key from the treap.
    pub fn delete(&self, key: &K) -> bool {
        self.inner.write().delete(key)
    }

    /// Clears the treap.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    /// Performs an in-order traversal.
    pub fn traverse<F>(&self, f: F)
    where
        F: FnMut(&K),
    {
        self.inner.read().traverse(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_treap_insert_and_lookup() {
        let mut treap = Treap::new();
        assert!(treap.is_empty());

        treap.insert(5, 10);
        treap.insert(3, 20);
        treap.insert(7, 15);

        assert_eq!(treap.len(), 3);
        assert!(treap.lookup(&5).is_some());
        assert!(treap.lookup(&3).is_some());
        assert!(treap.lookup(&7).is_some());
        assert!(treap.lookup(&1).is_none());
    }

    #[test]
    fn test_treap_delete() {
        let mut treap = Treap::new();
        treap.insert(5, 10);
        treap.insert(3, 20);
        treap.insert(7, 15);

        assert!(treap.delete(&5));
        assert_eq!(treap.len(), 2);
        assert!(treap.lookup(&5).is_none());
        assert!(treap.lookup(&3).is_some());
        assert!(treap.lookup(&7).is_some());

        assert!(!treap.delete(&99));
        assert_eq!(treap.len(), 2);
    }

    #[test]
    fn test_treap_clear() {
        let mut treap = Treap::new();
        treap.insert(5, 10);
        treap.insert(3, 20);
        treap.clear();

        assert!(treap.is_empty());
        assert_eq!(treap.len(), 0);
    }

    #[test]
    fn test_treap_traverse() {
        let mut treap = Treap::new();
        treap.insert(5, 10);
        treap.insert(3, 20);
        treap.insert(7, 15);
        treap.insert(1, 25);

        let mut keys = Vec::new();
        treap.traverse(|k| keys.push(*k));

        assert_eq!(keys, vec![1, 3, 5, 7]);
    }

    #[test]
    fn test_thread_safe_treap() {
        let treap = ThreadSafeTreap::new();
        treap.insert(5, 10);
        treap.insert(3, 20);

        assert_eq!(treap.len(), 2);
        assert!(treap.lookup(&5, |_| true).is_some());
        assert!(treap.delete(&3));
        assert_eq!(treap.len(), 1);
    }

    #[test]
    fn test_thread_safe_treap_clone() {
        let treap1 = ThreadSafeTreap::new();
        treap1.insert(5, 10);

        let treap2 = treap1.clone();
        treap2.insert(3, 20);

        assert_eq!(treap1.len(), 2);
        assert_eq!(treap2.len(), 2);
    }
}

//! Safe parse-option registry primitives for bootstrap/runtime.

use alloc::string::String;
use alloc::vec::Vec;

/// Argument mode for one option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionArgMode {
    None,
    Required,
    Optional,
}

/// Pure callback classification used by runtime registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptionCallbackKind {
    Default,
    Builtin,
    External,
}

/// One option registration record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionSpec {
    pub values: Vec<i32>,
    pub base_value: i32,
    pub smallest_value: i32,
    pub longopts: Vec<String>,
    pub callback: OptionCallbackKind,
    pub help: Option<String>,
    pub flags: u32,
    pub arg_mode: OptionArgMode,
}

impl OptionSpec {
    /// Returns true when this spec contains `value`.
    #[must_use]
    pub fn has_value(&self, value: i32) -> bool {
        self.values.contains(&value)
    }

    /// Returns true when this spec contains long option `name`.
    #[must_use]
    pub fn has_name(&self, name: &str) -> bool {
        self.longopts.iter().any(|current| current == name)
    }
}

/// Runtime-safe option registry model.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OptionRegistry {
    entries: Vec<OptionSpec>,
}

impl OptionRegistry {
    /// Returns a read-only view of registered entries.
    #[must_use]
    pub fn entries(&self) -> &[OptionSpec] {
        &self.entries
    }

    /// Inserts a spec while preserving sort by smallest value.
    ///
    /// Returns false when `base_value` is already registered.
    pub fn add(&mut self, spec: OptionSpec) -> bool {
        if self
            .entries
            .iter()
            .any(|entry| entry.values.contains(&spec.base_value))
        {
            return false;
        }
        self.entries.push(spec);
        self.entries.sort_by_key(|entry| entry.smallest_value);
        true
    }

    /// Removes one option by any matching value.
    pub fn remove_by_value(&mut self, value: i32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|entry| !entry.has_value(value));
        self.entries.len() != before
    }

    /// Finds entry index by option value.
    #[must_use]
    pub fn find_index_by_value(&self, value: i32) -> Option<usize> {
        self.entries.iter().position(|entry| entry.has_value(value))
    }

    /// Finds entry index by long option name.
    #[must_use]
    pub fn find_index_by_name(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|entry| entry.has_name(name))
    }
}


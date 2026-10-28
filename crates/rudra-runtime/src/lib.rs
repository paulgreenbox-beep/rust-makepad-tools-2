//! Small, application-agnostic runtime identity primitives.
//!
//! [`EntityId`] values are allocated monotonically by an owning [`Registry`].
//! They are meaningful only together with that owner and only for its lifetime;
//! they are not persistent, process-global, path-derived, or backend handles.
//!
//! Different entity types cannot be mixed:
//!
//! ```compile_fail
//! use rudra_runtime::{EntityId, Registry};
//!
//! struct Project;
//! struct Scene;
//!
//! let mut projects = Registry::new();
//! let project: EntityId<Project> = projects.insert(Project).unwrap();
//! let _scene: EntityId<Scene> = project;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::num::NonZeroU64;

/// A compact, strongly typed identifier for one runtime entity.
///
/// The numeric value is unique only within the allocator or registry that
/// created it. Value zero is unrepresentable and therefore reserved.
pub struct EntityId<T> {
    raw: NonZeroU64,
    marker: PhantomData<fn() -> T>,
}

impl<T> EntityId<T> {
    const fn from_non_zero(raw: NonZeroU64) -> Self {
        Self {
            raw,
            marker: PhantomData,
        }
    }

    /// Returns the non-zero runtime-local numeric value.
    pub const fn get(self) -> u64 {
        self.raw.get()
    }
}

impl<T> Copy for EntityId<T> {}

impl<T> Clone for EntityId<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for EntityId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<T> Eq for EntityId<T> {}

impl<T> PartialOrd for EntityId<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for EntityId<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<T> Hash for EntityId<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<T> fmt::Debug for EntityId<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EntityId")
            .field(&self.raw.get())
            .finish()
    }
}

impl<T> fmt::Display for EntityId<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw.get().fmt(formatter)
    }
}

/// Returned when the complete non-zero `u64` identifier space was consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdExhausted;

impl fmt::Display for IdExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime entity id space exhausted")
    }
}

impl Error for IdExhausted {}

/// Monotonic, owner-scoped allocator for one entity type.
///
/// Allocated values start at one, never wrap, and are never returned to the
/// allocator. Create a separate allocator for each independent owner/runtime.
pub struct IdAllocator<T> {
    next: Option<NonZeroU64>,
    marker: PhantomData<fn() -> T>,
}

impl<T> IdAllocator<T> {
    /// Creates an allocator whose first returned value is one.
    pub const fn new() -> Self {
        Self {
            next: NonZeroU64::new(1),
            marker: PhantomData,
        }
    }

    /// Allocates the next ID or fails without wrapping after `u64::MAX`.
    pub fn allocate(&mut self) -> Result<EntityId<T>, IdExhausted> {
        let current = self.next.ok_or(IdExhausted)?;
        self.next = current.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(EntityId::from_non_zero(current))
    }
}

impl<T> Default for IdAllocator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for IdAllocator<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdAllocator")
            .field("next", &self.next.map(NonZeroU64::get))
            .finish()
    }
}

/// An owning collection that assigns stable, typed runtime IDs.
///
/// Removal permanently stales an ID because the allocator is monotonic and no
/// free list exists. Lookup never falls back to another or "active" entity.
pub struct Registry<T> {
    allocator: IdAllocator<T>,
    entries: BTreeMap<EntityId<T>, T>,
}

impl<T> Registry<T> {
    /// Creates an empty registry with a fresh owner-scoped allocator.
    pub const fn new() -> Self {
        Self {
            allocator: IdAllocator::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a value and returns its newly allocated ID.
    pub fn insert(&mut self, value: T) -> Result<EntityId<T>, IdExhausted> {
        let id = self.allocator.allocate()?;
        let previous = self.entries.insert(id, value);
        debug_assert!(previous.is_none(), "monotonic allocator returned a live ID");
        Ok(id)
    }

    /// Returns a shared reference for an ID owned by this registry.
    pub fn get(&self, id: EntityId<T>) -> Option<&T> {
        self.entries.get(&id)
    }

    /// Returns a mutable reference for an ID owned by this registry.
    pub fn get_mut(&mut self, id: EntityId<T>) -> Option<&mut T> {
        self.entries.get_mut(&id)
    }

    /// Returns whether this registry currently owns the ID.
    pub fn contains(&self, id: EntityId<T>) -> bool {
        self.entries.contains_key(&id)
    }

    /// Removes and returns an entity, permanently staling its ID.
    pub fn remove(&mut self, id: EntityId<T>) -> Option<T> {
        self.entries.remove(&id)
    }

    /// Returns the number of live entities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the registry contains no live entities.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over live IDs and shared values in ascending ID order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (EntityId<T>, &T)> + '_ {
        self.entries.iter().map(|(id, value)| (*id, value))
    }

    /// Iterates over live IDs and mutable values in ascending ID order.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (EntityId<T>, &mut T)> + '_ {
        self.entries.iter_mut().map(|(id, value)| (*id, value))
    }
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for Registry<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("allocator", &self.allocator)
            .field("entries", &self.entries)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct Item(u32);

    #[test]
    fn allocation_starts_at_one_and_is_monotonic() {
        let mut allocator = IdAllocator::<Item>::new();
        assert_eq!(allocator.allocate().unwrap().get(), 1);
        assert_eq!(allocator.allocate().unwrap().get(), 2);
        assert_eq!(allocator.allocate().unwrap().get(), 3);
    }

    #[test]
    fn exhaustion_is_fail_safe_and_never_wraps_to_zero() {
        let mut allocator = IdAllocator::<Item> {
            next: NonZeroU64::new(u64::MAX),
            marker: PhantomData,
        };
        assert_eq!(allocator.allocate().unwrap().get(), u64::MAX);
        assert_eq!(allocator.allocate(), Err(IdExhausted));
        assert_eq!(allocator.allocate(), Err(IdExhausted));
    }

    #[test]
    fn registry_supports_lookup_mutation_iteration_and_removal() {
        let mut registry = Registry::new();
        assert!(registry.is_empty());
        let first = registry.insert(Item(10)).unwrap();
        let second = registry.insert(Item(20)).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(registry.contains(first));
        registry.get_mut(first).unwrap().0 = 11;
        assert_eq!(registry.get(first), Some(&Item(11)));
        assert_eq!(
            registry
                .iter()
                .map(|(id, item)| (id.get(), item.0))
                .collect::<Vec<_>>(),
            vec![(1, 11), (2, 20)]
        );
        assert_eq!(registry.remove(first), Some(Item(11)));
        assert_eq!(registry.get(first), None);
        assert_eq!(registry.get(second), Some(&Item(20)));
    }

    #[test]
    fn removed_ids_are_not_reused_and_duplicate_values_are_distinct() {
        let mut registry = Registry::new();
        let first = registry.insert(Item(7)).unwrap();
        let duplicate = registry.insert(Item(7)).unwrap();
        assert_ne!(first, duplicate);
        registry.remove(first);
        let next = registry.insert(Item(7)).unwrap();
        assert_eq!(next.get(), 3);
        assert!(!registry.contains(first));
    }

    #[test]
    fn registry_owners_are_independent_namespaces() {
        let mut left = Registry::new();
        let mut right = Registry::new();
        let left_id = left.insert(Item(1)).unwrap();
        let right_id = right.insert(Item(2)).unwrap();
        assert_eq!(left_id.get(), right_id.get());
        assert_eq!(left.get(left_id), Some(&Item(1)));
        assert_eq!(right.get(right_id), Some(&Item(2)));
    }

    #[test]
    fn id_debug_and_display_are_stable_and_address_free() {
        let id = Registry::new().insert(Item(1)).unwrap();
        assert_eq!(format!("{id:?}"), "EntityId(1)");
        assert_eq!(id.to_string(), "1");
    }
}

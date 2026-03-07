//! Compatibility layer for sync primitives and collections.
//! Under `std`, re-exports from `std::sync` and `std::collections`.
//! Under `no_std`, provides single-threaded alternatives using `core::cell`
//! and `hashbrown` for hash maps/sets.

// ---- Hash collections ----

#[cfg(feature = "std")]
pub use std::collections::{HashMap, HashSet, hash_map, hash_set};

#[cfg(not(feature = "std"))]
pub use hashbrown::{HashMap, HashSet, hash_map, hash_set};

// ---- Sync primitives ----

#[cfg(feature = "std")]
pub use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "std")]
pub use std::sync::PoisonError;

#[cfg(not(feature = "std"))]
pub use self::no_std_sync::*;

#[cfg(not(feature = "std"))]
#[allow(dead_code, unsafe_code)]
mod no_std_sync {
    pub use alloc::sync::Arc;
    use core::cell::{OnceCell, Ref, RefCell, RefMut};

    // ---- Mutex ----

    /// A no_std Mutex backed by RefCell (safe for single-threaded environments like zkVM guests).
    pub struct Mutex<T>(RefCell<T>);

    // SAFETY: In no_std zkVM guests, execution is single-threaded.
    unsafe impl<T: Send> Send for Mutex<T> {}
    unsafe impl<T: Send> Sync for Mutex<T> {}

    impl<T> Mutex<T> {
        pub const fn new(value: T) -> Self {
            Self(RefCell::new(value))
        }

        pub fn lock(&self) -> Result<MutexGuard<'_, T>, MutexError> {
            Ok(MutexGuard(self.0.borrow_mut()))
        }
    }

    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    pub struct MutexGuard<'a, T>(RefMut<'a, T>);

    impl<T> core::ops::Deref for MutexGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    #[derive(Debug)]
    pub struct MutexError;

    impl core::fmt::Display for MutexError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "mutex lock failed")
        }
    }

    // ---- RwLock ----

    /// A no_std RwLock backed by RefCell (safe for single-threaded environments like zkVM guests).
    pub struct RwLock<T>(RefCell<T>);

    // SAFETY: In no_std zkVM guests, execution is single-threaded.
    unsafe impl<T: Send> Send for RwLock<T> {}
    unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

    impl<T> RwLock<T> {
        pub const fn new(value: T) -> Self {
            Self(RefCell::new(value))
        }

        pub fn read(&self) -> Result<RwLockReadGuard<'_, T>, PoisonError<RwLockReadGuard<'_, T>>> {
            Ok(RwLockReadGuard(self.0.borrow()))
        }

        pub fn write(
            &self,
        ) -> Result<RwLockWriteGuard<'_, T>, PoisonError<RwLockWriteGuard<'_, T>>> {
            Ok(RwLockWriteGuard(self.0.borrow_mut()))
        }
    }

    impl<T: Default> Default for RwLock<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    pub struct RwLockReadGuard<'a, T>(Ref<'a, T>);

    impl<T> core::ops::Deref for RwLockReadGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    pub struct RwLockWriteGuard<'a, T>(RefMut<'a, T>);

    impl<T> core::ops::Deref for RwLockWriteGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T> core::ops::DerefMut for RwLockWriteGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    // ---- PoisonError ----

    /// A no_std PoisonError that wraps an inner guard value, matching std's API.
    #[derive(Debug)]
    pub struct PoisonError<T>(T);

    impl<T> PoisonError<T> {
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    impl<T> core::fmt::Display for PoisonError<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "poison error")
        }
    }

    // ---- OnceLock ----

    /// A no_std OnceLock backed by OnceCell (safe for single-threaded environments).
    pub struct OnceLock<T>(OnceCell<T>);

    // SAFETY: In no_std zkVM guests, execution is single-threaded.
    unsafe impl<T: Send> Send for OnceLock<T> {}
    unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}

    impl<T> OnceLock<T> {
        pub const fn new() -> Self {
            Self(OnceCell::new())
        }

        pub fn from(value: T) -> Self {
            let cell = OnceCell::new();
            let _ = cell.set(value);
            Self(cell)
        }

        pub fn get(&self) -> Option<&T> {
            self.0.get()
        }

        pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
            self.0.get_or_init(f)
        }

        pub fn set(&self, value: T) -> Result<(), T> {
            self.0.set(value)
        }

        pub fn take(&mut self) -> Option<T> {
            self.0.take()
        }
    }

    impl<T> Default for OnceLock<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T: Clone> Clone for OnceLock<T> {
        fn clone(&self) -> Self {
            match self.0.get() {
                Some(v) => Self::from(v.clone()),
                None => Self::new(),
            }
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for OnceLock<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("OnceLock").field(&self.0.get()).finish()
        }
    }
}

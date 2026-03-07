//! Compatibility layer for sync primitives.
//! Under `std`, re-exports from `std::sync`.
//! Under `no_std`, provides single-threaded alternatives using `core::cell`.

#[cfg(feature = "std")]
pub use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

#[cfg(not(feature = "std"))]
pub use self::no_std_sync::*;

#[cfg(not(feature = "std"))]
mod no_std_sync {
    pub use alloc::sync::Arc;
    use core::cell::{OnceCell, RefCell, RefMut};

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

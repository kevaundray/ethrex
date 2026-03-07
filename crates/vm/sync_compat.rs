//! Compatibility layer for sync primitives.
//! Under `std`, re-exports from `std::sync`.
//! Under `no_std`, provides single-threaded alternatives using `core::cell`
//! (safe for single-threaded environments like zkVM guests).

#[cfg(feature = "std")]
pub use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(not(feature = "std"))]
pub use self::no_std_sync::*;

#[cfg(not(feature = "std"))]
#[allow(dead_code, unsafe_code)]
mod no_std_sync {
    pub use alloc::sync::Arc;
    use core::cell::RefMut;

    /// A no_std Mutex backed by RefCell (safe for single-threaded environments like zkVM guests).
    pub struct Mutex<T>(core::cell::RefCell<T>);

    // SAFETY: In no_std zkVM guests, execution is single-threaded.
    unsafe impl<T: Send> Send for Mutex<T> {}
    unsafe impl<T: Send> Sync for Mutex<T> {}

    impl<T> Mutex<T> {
        pub const fn new(value: T) -> Self {
            Self(core::cell::RefCell::new(value))
        }

        pub fn lock(&self) -> Result<MutexGuard<'_, T>, MutexError> {
            Ok(MutexGuard(self.0.borrow_mut()))
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
}

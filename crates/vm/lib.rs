#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

mod db;
mod errors;
mod execution_result;
mod sync_compat;
#[cfg(feature = "std")]
pub mod tracing;
mod witness_db;

pub mod backends;

pub use backends::{BlockExecutionResult, Evm};
pub use db::{DynVmDatabase, VmDatabase};
pub use errors::EvmError;
pub use ethrex_levm::precompiles::PrecompileCache;
#[cfg(feature = "std")]
pub use ethrex_levm::precompiles::precompiles_for_fork;
pub use execution_result::ExecutionResult;
pub use witness_db::GuestProgramStateWrapper;
pub mod system_contracts;

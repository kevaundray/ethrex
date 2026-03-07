#![cfg_attr(not(feature = "std"), no_std)]
//! # LEVM - Lambda EVM
//!
//! A pure Rust implementation of the Ethereum Virtual Machine.
//!
//! ## Overview
//!
//! LEVM (Lambda EVM) is ethrex's native EVM implementation, designed for:
//! - **Correctness**: Full compatibility with Ethereum consensus tests
//! - **Performance**: Optimized opcode execution and memory management
//! - **Readability**: Clean, well-documented Rust code
//! - **Extensibility**: Modular design for easy feature additions
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                           VM                                 │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │  CallFrame  │  │   Memory    │  │       Stack         │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘ │
//! │                                                             │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
//! │  │  Substate   │  │ Precompiles │  │   Environment       │ │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    GeneralizedDatabase                       │
//! │              (Account state, storage, code)                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Components
//!
//! - [`vm::VM`]: Main EVM execution engine
//! - [`call_frame::CallFrame`]: Execution context for each call
//! - [`memory::Memory`]: EVM memory with expansion tracking
//! - [`environment::Environment`]: Block and transaction context
//! - [`precompiles`]: Native implementations of precompiled contracts
//! - [`hooks`]: Execution hooks for pre/post-execution logic and L2-specific behavior
//!
//! ## Supported Forks
//!
//! LEVM supports post-merge Ethereum forks:
//! - Paris (The Merge), Shanghai, Cancun, Prague, Osaka
//!
//! Note: ethrex is a post-merge client and does not support pre-merge forks.
//!
//! ## Usage
//!
//! ```ignore
//! use levm::{VM, Environment};
//!
//! // Create VM with database and environment
//! let mut vm = VM::new(env, db, &tx, tracer, debug_mode, vm_type);
//!
//! // Execute the transaction
//! let report = vm.execute()?;
//!
//! // Check execution result
//! if report.is_success() {
//!     println!("Gas used: {}", report.gas_used);
//! }
//! ```

extern crate alloc;


#[allow(unused_imports)]
pub(crate) mod sync_compat;

pub mod call_frame;
pub mod constants;
pub mod db;
pub mod debug;
pub mod environment;
pub mod errors;
pub mod execution_handlers;
pub mod gas_cost;
pub mod hooks;
pub mod memory;
pub mod opcode_handlers;
pub mod opcodes;
#[cfg(feature = "std")]
pub mod precompiles;
#[cfg(not(feature = "std"))]
pub mod precompiles {
    //! Stub precompiles module for no_std builds.
    //! In zkVM contexts, precompiles are handled by the host.
    use alloc::vec::Vec;
    use bytes::Bytes;
    use crate::errors::{ExceptionalHalt, VMError};
    use crate::vm::VMType;
    use ethrex_common::{Address, types::Fork};

    #[derive(Default)]
    pub struct PrecompileCache;

    impl PrecompileCache {
        pub fn new() -> Self {
            Self
        }
    }

    pub fn is_precompile(_address: &Address, _fork: Fork, _vm_type: VMType) -> bool {
        false
    }

    pub fn execute_precompile(
        _address: Address,
        _calldata: &Bytes,
        _gas_remaining: &mut u64,
        _fork: Fork,
        _cache: Option<&PrecompileCache>,
    ) -> Result<Bytes, VMError> {
        Err(VMError::ExceptionalHalt(ExceptionalHalt::InvalidOpcode))
    }

    pub const SIZE_PRECOMPILES_PRE_CANCUN: u64 = 9;
    pub const SIZE_PRECOMPILES_CANCUN: u64 = 10;
    pub const SIZE_PRECOMPILES_PRAGUE: u64 = 17;
}
pub mod tracing;
pub mod utils;
pub mod vm;
pub use environment::*;
pub mod account;
#[cfg(feature = "perf_opcode_timings")]
pub mod timings;

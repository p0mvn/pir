//! SimplePIR: Single-round PIR with O(√N) query and O(√N × record_size) answer.
//!
//! This module implements the SimplePIR protocol from the paper.

mod client;
mod server;

pub use client::{PirClient, QueryState, SimplePir};
pub use server::PirServer;


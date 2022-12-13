pub mod consensus;

pub(crate) mod proposal;

mod abba;
mod broadcaster;
mod bundle;
mod hash;
mod vcbc;

pub type NodeId = usize;



/// A proposed data with the proof inside. It is the same as $(w, π)$ in the spec.
pub type Proposal = Vec<u8>;

/// MessageValidity is same as &Q_{ID}$ ins spec: a global polynomial-time computable
/// predicate QID known to all parties, which is determined by an external application.
/// Each party may propose a value v together with a proof π that should satisfy QID .
pub type MessageValidity = fn(NodeId, &Proposal) -> bool;

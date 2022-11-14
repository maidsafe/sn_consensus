pub mod consensus;

pub(crate) mod proposal;

//mod abba;
mod broadcaster;
mod bundle;
mod hash;
mod vcbc;

pub type NodeId = usize;
pub type ProposalChecker = fn(&proposal::Proposal) -> bool;

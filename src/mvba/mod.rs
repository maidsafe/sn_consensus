pub mod consensus;

pub(crate) mod proposal;

mod abba;
mod broadcaster;
mod bundle;
mod crypto;
mod doc;
mod vcbc;

pub type ProposalChecker = fn(&proposal::Proposal) -> bool;

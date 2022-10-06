
pub type Hash = [u8;32];

pub trait Proposal {
    fn hash() -> Hash;
}

pub trait ProposalService<P:Proposal> {
    fn get_proposal() -> Result<P>;
    fn check_proposal(p: P) -> bool;
    fn decided_proposal(p: P);
}


mod consensus;
mod abba;
mod rbc;


type Hash = [u8;32];

trait Proposal {
    fn hash() -> Hash;
}

trait ProposalService<P:Proposal> {
    fn get_proposal() -> Result<P>;
    fn check_proposal(p: P) -> bool;
    fn decided_proposal(p: P);
}

trait GossipService {
    fn broadcast_msg(msg: Serializable) -> Result<()>;
}

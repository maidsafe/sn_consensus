use crate::mvba::proposal::Proposal;


#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum Message {
    Propose(Proposal),
    Echo(Proposal),
}

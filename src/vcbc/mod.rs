use crate::{crypto::public::PubKey, ProposalService};

use self::payload::Message;

mod deliver;
mod echo;
mod error;
pub  mod log;
mod payload;
mod propose;

pub trait State {
    fn process_message(self: Box<Self>, log: &log::Log) -> Box<dyn State>;
}

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub struct VCBC {
    threshold: u32,
    log: log::Log, /// TODO: can we move log into state? better encapsulation?
    self_key: PubKey,
    state: Option<Box<dyn State>>,
    proposal_service: ProposalService,
}

impl VCBC {
    pub fn new(
        self_key: &PubKey,
        proposer: &PubKey,
        parties: &Vec<PubKey>,
        threshold: u32,
        proposal_service: &ProposalService,
    ) -> Self {
        Self {
            threshold,
            log: log::Log::new(parties, proposer),
            self_key: self_key.clone(),
            state: Some(Box::new(propose::ProposeState::new())),
            proposal_service: proposal_service.clone(),
        }
    }

    pub fn propose(&mut self) {
        if self.self_key == self.proposal_service.proposal.proposer {
            // TODO: broadcast proposal

            if let Some(_) = self.state.take() {
                self.state = Some(Box::new(echo::EchoState::new()))
            }
        }
    }

    pub fn process_message(&mut self, msg: &Message) -> Box<dyn State> {
        
        todo!()
    }
}

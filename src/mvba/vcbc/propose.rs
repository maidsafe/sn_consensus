use crate::mvba::crypto::signature::Signature;

use super::echo;
use super::echo::EchoState;
use super::log;
use super::message::Message;
use super::State;

pub(super) struct ProposeState {}

impl State for ProposeState {
    fn enter(self:Box<Self>, log: &mut log::Log) -> Box<dyn State> {
        todo!()
    }

    fn decide(self: Box<Self>, log: &mut log::Log) -> Box<dyn State> {
        match &log.proposal {
            Some(proposal) => {
                let msg = Message {
                    tag: "v-propose".to_string(),
                    proposal: proposal.clone(),
                };
                log.broadcaster.borrow_mut().broadcast(msg);
                let echo_state = Box::new(EchoState {});
                echo_state.enter(log)

            }
            None => self,
        }
    }

    fn name(&self) -> String {
        "propose state".to_string()
    }
}

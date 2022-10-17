use super::deliver::DeliverState;
use super::log;
use super::State;
use super::message::Message;

pub(super) struct EchoState {}

impl State for EchoState {
    fn enter(self:Box<Self>, log: &mut log::Log) -> Box<dyn State> {
        let msg = Message {
            tag: "v-echo,".to_string(),
            proposal: log.proposal.as_ref().unwrap().clone(),
        };
        log.broadcaster.borrow_mut().broadcast(msg);
        self.decide(log)
    }

    fn decide(self: Box<Self>, log: &mut log::Log) -> Box<dyn State> {
        if log.echos.len() >= log.super_majority_num() {
            let state = Box::new(DeliverState {});
            state.enter(log)
        } else {
            self
        }
    }

    fn name(&self) -> String {
        "echo state".to_string()
    }
}

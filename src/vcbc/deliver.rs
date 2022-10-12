use super::log;
use super::State;

pub(super) struct DeliverState {}

impl DeliverState {
    pub fn new() -> Self {
        DeliverState {}
    }
}

impl State for DeliverState {
    fn process_message(self:Box<Self>, log: &log::Log) -> Box<dyn State> {
        todo!()
    }
}

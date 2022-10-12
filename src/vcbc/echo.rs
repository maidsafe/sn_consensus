use super::log;
use super::State;

pub(super) struct EchoState {}

impl EchoState {
    pub fn new() -> Self {
        EchoState {}
    }
}

impl State for EchoState {
    fn process_message(self:Box<Self>, log: &log::Log) -> Box<dyn State> {
        todo!()
    }
}

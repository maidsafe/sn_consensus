use super::log;
use super::State;

pub(super) struct ProposeState {}

impl ProposeState {
    pub fn new() -> Self {
        ProposeState {}
    }
}

impl State for ProposeState {
    fn process_message(self:Box<Self>, log: &log::Log) -> Box<dyn State> {
        todo!()
    }
}

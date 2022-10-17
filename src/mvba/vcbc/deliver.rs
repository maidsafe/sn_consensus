use super::log;
use super::State;

pub(super) struct DeliverState {}

impl State for DeliverState {
    fn enter(self: Box<Self>, log: &mut log::Log) -> Box<dyn State> {
        log.delivered = true;
        self
    }

    fn decide(self: Box<Self>, _: &mut log::Log) -> Box<dyn State> {
        self
    }

    fn name(&self) -> String {
        "deliver state".to_string()
    }
}

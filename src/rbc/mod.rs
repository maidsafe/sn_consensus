use crate::GossipService;

mod log;


pub struct RBC {
    log: log::Log,
    gossip_service: Box<dyn GossipService>,
}

impl RBC {
    pub fn new() -> Self {
        todo!()
    }
}
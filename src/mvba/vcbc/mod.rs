pub(super) mod context;
pub(super) mod message;
pub(super) mod state;

mod broadcast;
//mod deliver;
//mod echo;
mod error;
//mod propose;
mod send;

use self::broadcast::BroadcastState;
use self::error::Result;
use self::message::{Message, MSG_ACTION_C_BROADCAST};
use self::state::State;
use super::{NodeId};
use crate::mvba::broadcaster::Broadcaster;
use blsttc::SecretKeyShare;
use std::cell::RefCell;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

// Protocol VCBC for verifiable and authenticated consistent broadcast.
pub(crate) struct Vcbc {
    i: NodeId, // this is same as $i$ in spec
    ctx: context::Context,
    state: Box<dyn State>,
}

impl Vcbc {
    pub fn new(
        number: usize,
        threshold: usize,
        i: NodeId,
        id: String,
        j: NodeId,
        s: u32,
        broadcaster: Rc<RefCell<Broadcaster>>,
        sec_key_share: SecretKeyShare,
    ) -> Self {
        Self {
            i,
            ctx: context::Context::new(number, threshold, id, j, s, broadcaster, sec_key_share),
            state: Box::new(BroadcastState),
        }
    }

    // sending c-broadcast messages
    pub fn c_broadcast(&mut self, m: Vec<u8>) -> Result<()> {
        debug_assert_eq!(self.i, self.ctx.j);

        let msg = Message {
            id: self.ctx.id.clone(),
            j: self.i,
            s: self.ctx.s,
            action: MSG_ACTION_C_BROADCAST.to_string(),
            m,
            sig: None,
        };
        self.ctx.broadcast(&msg);
        self.process_message(self.i, msg)
    }

    pub fn process_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        log::debug!("{} adding message: {:?}", self.state.name(), msg);


        self.ctx.log_message(sender, msg)?;
        if let Some(s) = self.state.decide(&mut self.ctx)? {
            self.state = s;
        }

        Ok(())
    }

    pub fn is_delivered(&self) -> bool {
        self.ctx.delivered
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;

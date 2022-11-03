use super::context::Context;
use super::error::Result;
use super::message::{Message, MSG_ACTION_C_BROADCAST, MSG_ACTION_C_SEND};
use super::send::SendState;
use super::State;
use crate::mvba::NodeId;

pub(super) struct BroadcastState;

impl State for BroadcastState {
    fn enter(self: Box<Self>, _ctx: &mut Context) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn decide(&self, ctx: &mut Context) -> Result<Option<Box<dyn State>>> {
        match ctx.message_log.get(MSG_ACTION_C_BROADCAST) {
            Some(msgs) => {
                let broadcast_msg = &msgs[0].1;
                let send_msg = Message {
                    id: ctx.id.clone(),
                    j: ctx.j,
                    s: ctx.s,
                    action: MSG_ACTION_C_SEND.to_string(),
                    m: broadcast_msg.m.clone(),
                    sig: None,
                };

                ctx.broadcast(&send_msg);
                let state = Box::new(SendState);
                Ok(Some(state.enter(ctx)?))
            }
            None => Ok(None),
        }
    }

    fn name(&self) -> String {
        "c-broadcast state".to_string()
    }
}

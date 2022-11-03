use crate::mvba::hash::hash;
use crate::mvba::NodeId;

use super::context::Context;
use super::error::Result;
use super::message::{Message, MSG_ACTION_C_READY, MSG_ACTION_C_SEND};
use super::State;

pub(super) struct SendState;

impl State for SendState {
    fn enter(self: Box<Self>, _ctx: &mut Context) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn decide(&self, ctx: &mut Context) -> Result<Option<Box<dyn State>>> {
        match ctx.message_log.get(MSG_ACTION_C_SEND) {
            Some(msgs) => {
                for (sender, msg) in msgs {
                    if *sender == ctx.j && ctx.m_bar == None {
                        ctx.m_bar = Some(msg.m.clone());

                        // compute an $S_1-signature$ share $ν$ on $(ID.j.s, c-ready, H(m))$
                        let d = hash(&msg.m);
                        let mut ready_msg = Message {
                            id: ctx.id.clone(),
                            j: ctx.j,
                            s: ctx.s,
                            action: MSG_ACTION_C_READY.to_string(),
                            m: d.0.to_vec(),
                            sig: None,
                        };
                        let sig_bytes = bincode::serialize(&msg).unwrap(); // TODO: bincode or??
                        let s1 = ctx.sec_key_share.sign(sig_bytes);
                        ready_msg.sig = Some(s1.to_bytes().to_vec());

                        ctx.broadcast(&ready_msg);
                    }
                }
                todo!()
            }
            None => Ok(None),
        }
    }

    fn name(&self) -> String {
        "c-send state".to_string()
    }
}

use super::{
    abba::{self, Abba},
    bundle::{Bundle, Outgoing},
    error::Error,
    error::Result,
    hash::Hash32,
    mvba::{self, Mvba},
    vcbc::{self},
    Proposal,
};
use crate::mvba::{broadcaster::Broadcaster, vcbc::Vcbc, MessageValidity, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub struct Consensus {
    self_id: NodeId,
    abba_map: HashMap<NodeId, Abba>,
    vcbc_map: HashMap<NodeId, Vcbc>,
    mvba: Mvba,
    finished: bool,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        id: String,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        message_validity: MessageValidity,
    ) -> Consensus {
        let broadcaster = Broadcaster::new(self_id);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));
        let mut abba_map = HashMap::new();
        let mut vcbc_map = HashMap::new();

        for party in &parties {
            let vcbc = Vcbc::new(
                id.clone(),
                self_id,
                *party,
                pub_key_set.clone(),
                sec_key_share.clone(),
                message_validity,
                broadcaster_rc.clone(),
            );
            vcbc_map.insert(*party, vcbc).unwrap();

            let abba = Abba::new(
                id.clone(),
                self_id,
                *party,
                pub_key_set.clone(),
                sec_key_share.clone(),
                broadcaster_rc.clone(),
            );
            abba_map.insert(*party, abba).unwrap();
        }

        let mvba = Mvba::new(
            id,
            self_id,
            sec_key_share,
            pub_key_set,
            parties,
            broadcaster_rc.clone(),
        );

        Consensus {
            self_id,
            vcbc_map,
            abba_map,
            mvba,
            finished: false,
            broadcaster: broadcaster_rc,
        }
    }

    /// starts the consensus by proposing the `proposal`.
    pub fn propose(&mut self, proposal: Proposal) -> Result<Vec<Outgoing>> {
        match self.vcbc_map.get_mut(&self.self_id) {
            Some(vcbc) => {
                // verifiably authenticatedly c-broadcast message (v-echo, w, π) tagged with ID|vcbc.i.0
                vcbc.c_broadcast(proposal)?;
            }
            None => {
                log::warn!("this node is an observer node")
            }
        }
        Ok(self.broadcaster.borrow_mut().take_outgoings())
    }

    pub fn process_bundle(&mut self, bundle: &Bundle) -> Result<Vec<Outgoing>> {
        if self.finished {
            return Ok(vec![]);
        }

        match bundle.module.as_ref() {
            vcbc::MODULE_NAME => match self.vcbc_map.get_mut(&bundle.initiator) {
                Some(vcbc) => {
                    let msg = bincode::deserialize(&bundle.payload)?;
                    vcbc.receive_message(bundle.initiator, msg)?;
                    if vcbc.is_delivered() {
                        let (proposal, sig) = vcbc.delivered_message();
                        self.mvba.set_proposal(bundle.initiator, proposal, sig)?;
                    }
                }
                None => return Err(Error::UnknownNodeId(bundle.initiator)),
            },
            abba::MODULE_NAME => match self.abba_map.get_mut(&bundle.initiator) {
                Some(abba) => {
                    let msg = bincode::deserialize(&bundle.payload)?;
                    abba.receive_message(bundle.initiator, msg)?;
                    if abba.is_decided() {
                        if abba.decided_value() {
                            self.finished = true;
                        } else {
                            self.mvba.move_to_next_proposal()?;
                        }
                    }
                }
                None => {
                    return Err(Error::UnknownNodeId(bundle.initiator));
                }
            },
            mvba::MODULE_NAME => {
                let msg = bincode::deserialize(&bundle.payload)?;
                self.mvba.receive_message(msg)?;
                if self.mvba.is_completed() {
                    let abba = self.abba_map.get_mut(&bundle.initiator).unwrap();
                    if self.mvba.completed_vote() {
                        abba.pre_vote_zero()?;
                    } else {
                        let (proposal, sig) = self.mvba.completed_vote_one();
                        let digest = Hash32::calculate(proposal);
                        abba.pre_vote_one(digest, sig)?;
                    }
                }
            }

            _ => {
                return Err(Error::InvalidMessage(format!(
                    "unknown module {}",
                    bundle.module
                )));
            }
        };

        Ok(self.broadcaster.borrow_mut().take_outgoings())
    }
}

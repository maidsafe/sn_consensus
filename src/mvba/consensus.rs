use super::{
    abba::{self, Abba},
    bundle::{Bundle, Outgoing},
    error::Error,
    error::Result,
    mvba::{self, Mvba},
    vcbc::{self},
    Proposal,
};
use crate::mvba::{broadcaster::Broadcaster, vcbc::Vcbc, MessageValidity, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(crate) const MVBA_MODULE_NAME: &str = "mvba";

pub struct Consensus {
    pub id: String, // this is same as $ID$ in spec
    self_id: NodeId,
    pub_key_set: PublicKeySet,
    parties: Vec<NodeId>,
    abba_map: HashMap<NodeId, Abba>,
    vcbc_map: HashMap<NodeId, Vcbc>,
    mvba: Mvba,
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
        let broadcaster = Broadcaster::new(id.clone(), self_id);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));
        let mut abba_map = HashMap::new();
        let mut vcbc_map = HashMap::new();

        for party in &parties {
            let vcbc = Vcbc::new(
                self_id,
                *party,
                pub_key_set.clone(),
                sec_key_share.clone(),
                message_validity,
                broadcaster_rc.clone(),
            );
            vcbc_map.insert(*party, vcbc).unwrap();

            let abba = Abba::new(
                self_id,
                *party,
                pub_key_set.clone(),
                sec_key_share.clone(),
                broadcaster_rc.clone(),
            );
            abba_map.insert(*party, abba).unwrap();
        }

        let mvba = Mvba::new(
            self_id,
            sec_key_share,
            pub_key_set.clone(),
            parties.clone(),
            broadcaster_rc.clone(),
        );

        Consensus {
            id,
            self_id,
            pub_key_set,
            parties,
            vcbc_map,
            abba_map,
            mvba,
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
        if bundle.id != self.id {
            return Err(Error::InvalidMessage(format!(
                "invalid ID. expected: {}, got {}",
                self.id, bundle.id
            )));
        }

        match bundle.module.as_ref() {
            vcbc::MODULE_NAME => match self.vcbc_map.get_mut(&bundle.initiator) {
                Some(vcbc) => {
                    let msg = bincode::deserialize(&bundle.payload)?;
                    vcbc.receive_message(bundle.initiator, msg)?;
                }
                None => return Err(Error::UnknownNodeId(bundle.initiator)),
            },
            abba::MODULE_NAME => match self.abba_map.get_mut(&bundle.initiator) {
                Some(abba) => {
                    let msg = bincode::deserialize(&bundle.payload)?;
                    abba.receive_message(bundle.initiator, msg)?;
                }
                None => {
                    return Err(Error::UnknownNodeId(bundle.initiator));
                }
            },
            mvba::MODULE_NAME => {
                let msg = bincode::deserialize(&bundle.payload)?;
                self.mvba.receive_message(msg)?;
            }

            _ => {
                return Err(Error::InvalidMessage(format!(
                    "unknown module {}",
                    bundle.module
                )));
            }
        };

        let mut delivered_count = 0;
        for vcbc in self.vcbc_map.values() {
            if vcbc.is_delivered() {
                delivered_count += 1;
            }
        }

        Ok(self.broadcaster.borrow_mut().take_outgoings())
    }
}

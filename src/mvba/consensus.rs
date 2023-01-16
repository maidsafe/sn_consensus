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
    id: String,
    self_id: NodeId,
    abba_map: HashMap<NodeId, Abba>,
    vcbc_map: HashMap<NodeId, Vcbc>,
    mvba: Mvba,
    decided_party: Option<NodeId>,
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
            vcbc_map.insert(*party, vcbc);

            let abba = Abba::new(
                id.clone(),
                self_id,
                *party,
                pub_key_set.clone(),
                sec_key_share.clone(),
                broadcaster_rc.clone(),
            );
            abba_map.insert(*party, abba);
        }

        let mvba = Mvba::new(
            id.clone(),
            self_id,
            sec_key_share,
            pub_key_set,
            parties,
            broadcaster_rc.clone(),
        );

        Consensus {
            id,
            self_id,
            vcbc_map,
            abba_map,
            mvba,
            decided_party: None,
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
        if self.decided_party.is_some() {
            return Ok(vec![]);
        }

        match bundle.module.as_ref() {
            vcbc::MODULE_NAME => match bundle.target {
                Some(target) => match self.vcbc_map.get_mut(&target) {
                    Some(vcbc) => {
                        let msg = bincode::deserialize(&bundle.payload)?;
                        vcbc.receive_message(bundle.initiator, msg)?;
                        if vcbc.is_delivered() {
                            let abba = self.abba_map.get_mut(&target).unwrap();
                            if abba.is_decided() {
                                if abba.decided_value() {
                                    self.decided_party = Some(target.clone());
                                }
                            }

                            let (proposal, sig) = vcbc.delivered_message();
                            self.mvba.set_proposal(target, proposal, sig)?;
                        }
                    }
                    None => {
                        return Err(Error::InvalidMessage(format!("target {target} not found")))
                    }
                },
                None => return Err(Error::InvalidMessage("no target is defined".to_string())),
            },

            abba::MODULE_NAME => match bundle.target {
                Some(target) => match self.abba_map.get_mut(&target) {
                    Some(abba) => {
                        let msg = bincode::deserialize(&bundle.payload)?;
                        abba.receive_message(bundle.initiator, msg)?;
                        if abba.is_decided() {
                            if abba.decided_value() {
                                let vcbc = self.vcbc_map.get_mut(&target).unwrap();
                                if vcbc.is_delivered() {
                                    self.decided_party = Some(target.clone());
                                } else {
                                    // abba is finished but still we don't have the proposal
                                    // request it from the initiator
                                    let data = vcbc::make_c_request_message(&self.id, target)?;

                                    self.broadcaster.borrow_mut().send_to(
                                        vcbc::MODULE_NAME,
                                        Some(target),
                                        data,
                                        bundle.initiator,
                                    );
                                }
                            } else {
                                if !self.mvba.move_to_next_proposal()? {
                                    log::warn!("no more proposal");
                                }
                            }
                        }
                    }
                    None => {
                        return Err(Error::InvalidMessage(format!("target {target} not found")))
                    }
                },
                None => return Err(Error::InvalidMessage("no target is defined".to_string())),
            },
            mvba::MODULE_NAME => {
                let msg = bincode::deserialize(&bundle.payload)?;
                self.mvba.receive_message(msg)?;
                if self.mvba.is_completed() {
                    let abba = self
                        .abba_map
                        .get_mut(&self.mvba.current_proposer())
                        .unwrap();

                    if self.mvba.completed_vote() {
                        if let Some((proposal, sig)) = self.mvba.completed_vote_one() {
                            let digest = Hash32::calculate(proposal);
                            abba.pre_vote_one(digest, sig.clone())?;
                        }
                    } else {
                        abba.pre_vote_zero()?;
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

#[cfg(test)]
mod tests {
    use super::Consensus;
    use crate::mvba::{bundle::Outgoing, *};
    use blsttc::SecretKeySet;
    use log::LevelFilter;
    use rand::{thread_rng, Rng};

    fn valid_proposal(_: NodeId, _: &Proposal) -> bool {
        true
    }

    struct TestNet {
        cons: Vec<Consensus>,
        msgs: Vec<Outgoing>,
    }

    impl TestNet {
        const PARTY_X: NodeId = 0;
        const PARTY_Y: NodeId = 1;
        const PARTY_B: NodeId = 2;
        const PARTY_S: NodeId = 3;

        pub fn new() -> Self {
            let _ = env_logger::builder()
                .is_test(true)
                .filter_level(LevelFilter::Trace)
                .try_init();

            let id = "test-id".to_string();
            let mut rng = thread_rng();
            let sec_key_set = SecretKeySet::random(2, &mut rng);
            let parties = vec![
                TestNet::PARTY_X,
                TestNet::PARTY_Y,
                TestNet::PARTY_B,
                TestNet::PARTY_S,
            ];
            let mut cons = Vec::new();

            for p in &parties {
                let consensus = Consensus::init(
                    id.clone(),
                    p.clone(),
                    sec_key_set.secret_key_share(p),
                    sec_key_set.public_keys(),
                    parties.clone(),
                    valid_proposal,
                );

                cons.push(consensus);
            }

            Self {
                cons,
                msgs: Vec::new(),
            }
        }
    }

    #[test]
    fn test_random() {
        let mut net = TestNet::new();
        let mut rng = thread_rng();

        for c in &mut net.cons {
            let proposal = (0..100).map(|_| rng.gen_range(0..64)).collect();
            let mut msgs = c.propose(proposal).unwrap();
            net.msgs.append(&mut msgs);
        }

        loop {
            let rand_index = rng.gen_range(0..net.msgs.len());
            let rand_msg = &net.msgs.remove(rand_index);
            let mut msgs = Vec::new();
            log::debug!("random message: {:?}", rand_msg);

            for c in &mut net.cons {
                msgs.append(&mut match rand_msg {
                    Outgoing::Direct(id, bundle) => {
                        if id == &c.self_id {
                            c.process_bundle(&bundle).unwrap()
                        } else {
                            Vec::new()
                        }
                    }
                    Outgoing::Gossip(bundle) => c.process_bundle(bundle).unwrap(),
                });
            }

            net.msgs.append(&mut msgs);

            let mut halted = true;
            for c in &mut net.cons {
                if !c.decided_party.is_some() {
                    halted = false;
                    break;
                } else {
                    log::info!(
                        "consensus {:?} finished for {:?} with {:?}",
                        c.self_id,
                        c.decided_party.unwrap(),
                        c.abba_map
                            .get(&c.decided_party.unwrap())
                            .unwrap()
                            .decided_value()
                    );
                }
            }

            if halted {
                break;
            }
        }
    }
}

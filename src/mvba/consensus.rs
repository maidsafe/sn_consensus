use super::{
    abba::Abba,
    bundle::Message::*,
    bundle::{Bundle, Outgoing},
    error::Error,
    error::Result,
    hash::Hash32,
    mvba::Mvba,
    tag::{Domain, Tag},
    vcbc, Proof,
};
use crate::mvba::{broadcaster::Broadcaster, vcbc::Vcbc, Decision, MessageValidity, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare};
use serde::Serialize;
use std::{collections::HashMap, fmt::Debug};

pub struct Consensus<P: Debug + Clone + Serialize + Eq> {
    domain: Domain,
    self_id: NodeId,
    abba_map: HashMap<NodeId, Abba>,
    vcbc_map: HashMap<NodeId, Vcbc<P>>,
    mvba: Mvba<P>,
    decided_proposer: Option<NodeId>,
    decided_proposal: Option<P>,
    broadcaster: Broadcaster<P>,
}

impl<P: Debug + Clone + Serialize + Eq> Consensus<P> {
    pub fn init(
        domain: Domain,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        message_validity: MessageValidity<P>,
    ) -> Self {
        let broadcaster = Broadcaster::new(self_id);
        let mut abba_map = HashMap::new();
        let mut vcbc_map = HashMap::new();

        for party in &parties {
            let tag = Tag::new(domain.clone(), *party);
            let vcbc = Vcbc::new(
                tag.clone(),
                self_id,
                pub_key_set.clone(),
                sec_key_share.clone(),
                message_validity,
            );
            vcbc_map.insert(*party, vcbc);

            let abba = Abba::new(tag, self_id, pub_key_set.clone(), sec_key_share.clone());
            abba_map.insert(*party, abba);
        }

        let mvba = Mvba::new(domain.clone(), self_id, sec_key_share, pub_key_set, parties);

        Consensus {
            domain,
            self_id,
            vcbc_map,
            abba_map,
            mvba,
            decided_proposer: None,
            decided_proposal: None,
            broadcaster,
        }
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn pub_key_set(&self) -> PublicKeySet {
        self.mvba.pub_key_set()
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    /// starts the consensus by proposing the `proposal`.
    pub fn propose(&mut self, proposal: P) -> Result<Vec<Outgoing<P>>> {
        match self.vcbc_map.get_mut(&self.self_id) {
            Some(vcbc) => {
                // verifiably authenticatedly c-broadcast message (v-echo, w, π) tagged with ID|vcbc.i.0
                vcbc.c_broadcast(proposal, &mut self.broadcaster)?;
            }
            None => {
                log::warn!("this node is an observer node")
            }
        }
        Ok(self.broadcaster.take_outgoings())
    }

    pub fn process_bundle(&mut self, bundle: &Bundle<P>) -> Result<Vec<Outgoing<P>>> {
        if self.decided_proposal.is_some() {
            return Ok(vec![]);
        }

        match &bundle.message {
            Vcbc(msg) => match bundle.target {
                Some(target) => match self.vcbc_map.get_mut(&target) {
                    Some(vcbc) => {
                        vcbc.receive_message(bundle.initiator, msg.clone(), &mut self.broadcaster)?;
                        if let Some((proposal, sig)) = vcbc.read_delivered() {
                            // Check if we have agreed on this proposal before.
                            //    There might be a situation that we receive the agreement
                            //    before receiving the actual proposal.

                            if self.decided_proposer.is_some() {
                                // We re done! We have both proposal and agreement
                                log::info!("halted. proposer: {target}");
                                self.decided_proposal = Some(proposal);
                            } else {
                                self.mvba.set_proposal(
                                    target,
                                    proposal,
                                    sig,
                                    &mut self.broadcaster,
                                )?;
                            }
                        }
                    }
                    None => {
                        return Err(Error::InvalidMessage(format!("target {target} not found")))
                    }
                },
                None => return Err(Error::InvalidMessage("no target is defined".to_string())),
            },

            Abba(msg) => match bundle.target {
                Some(target) => match self.abba_map.get_mut(&target) {
                    Some(abba) => {
                        abba.receive_message(bundle.initiator, msg.clone(), &mut self.broadcaster)?;
                        if let Some(decided_value) = abba.is_decided() {
                            if decided_value {
                                self.decided_proposer = Some(target);

                                let vcbc = self
                                    .vcbc_map
                                    .get_mut(&target)
                                    .expect("vcbc_map is not initialized");
                                if let Some((proposal, _)) = vcbc.read_delivered() {
                                    // We re done! We have both proposal and agreement
                                    log::info!("halted. proposer: {target}");
                                    self.decided_proposal = Some(proposal);
                                } else {
                                    // abba is finished but still we don't have the proposal
                                    // request it from the initiator
                                    let tag = Tag::new(self.domain.clone(), target);
                                    let bundle_message = vcbc::make_c_request_message(tag);

                                    self.broadcaster.broadcast(Some(target), bundle_message);
                                }
                            } else if self.mvba.current_proposer()? == target
                                && !self.mvba.move_to_next_proposal(&mut self.broadcaster)?
                            {
                                log::warn!("party {} has no more proposal", self.self_id);
                            }
                        }
                    }
                    None => {
                        return Err(Error::InvalidMessage(format!("target {target} not found")))
                    }
                },
                None => return Err(Error::InvalidMessage("no target is defined".to_string())),
            },
            Mvba(msg) => {
                self.mvba
                    .receive_message(msg.clone(), &mut self.broadcaster)?;
            }
        };

        if let Some(completed_vote) = self.mvba.completed_vote() {
            let abba = self
                .abba_map
                .get_mut(&self.mvba.current_proposer()?)
                .expect("mvba is not initialized");

            if completed_vote {
                // The proposal is c-delivered and we have proof for that.
                // Let's start binary agreement by voting 1
                if let Some((proposal, sig)) = self.mvba.completed_vote_value()? {
                    let digest = Hash32::calculate(proposal)?;
                    abba.pre_vote_one(digest, sig.clone(), &mut self.broadcaster)?;
                }
            } else {
                // The proposal is NOT c-delivered.
                // Let's start binary agreement by voting 0,
                abba.pre_vote_zero(&mut self.broadcaster)?;
            }
        }

        Ok(self.broadcaster.take_outgoings())
    }

    pub fn decided_proposal(&self) -> Option<Decision<P>> {
        let proposer = self.decided_proposer.as_ref()?;
        let abba = self.abba_map.get(proposer)?;
        let vcbc = self.vcbc_map.get(proposer)?;
        let (proposal, vcbc_sig) = vcbc.read_delivered()?;
        let (value, abba_sig, round) = abba.decided_value()?;
        if value {
            let proof = Proof {
                proposer: *proposer,
                abba_round: round,
                abba_signature: abba_sig.clone(),
                vcbc_signature: vcbc_sig,
            };
            Some(Decision {
                domain: self.domain.clone(),
                proposal,
                proof,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Consensus;
    use crate::mvba::{bundle::Outgoing, tag::Domain, *};

    use blsttc::SecretKeySet;
    use quickcheck_macros::quickcheck;
    use rand::{thread_rng, Rng, SeedableRng};

    fn valid_proposal(_id: NodeId, _: &char) -> bool {
        true
    }

    struct TestNet {
        cons: Vec<Consensus<char>>,
        buffer: Vec<Outgoing<char>>,
        sks: SecretKeySet,
    }

    impl TestNet {
        pub fn new() -> Self {
            let domain = Domain::new("test-domain", 0);
            let mut rng = thread_rng();
            //let (t, n) = (5, 7);
            let (t, n) = (2, 4);
            let sks = SecretKeySet::random(t, &mut rng);
            let mut parties = Vec::new();
            let mut cons = Vec::new();

            for index in 0..n {
                parties.push(index as usize)
            }

            for p in &parties {
                let consensus = Consensus::init(
                    domain.clone(),
                    *p,
                    sks.secret_key_share(p),
                    sks.public_keys(),
                    parties.clone(),
                    valid_proposal,
                );

                cons.push(consensus);
            }

            Self {
                cons,
                sks,
                buffer: Vec::new(),
            }
        }
    }

    #[test]
    fn test_prevent_decision_conflict() {
        let seed: u128 = 239389896331702023721706851822556999354;
        let mut seed_buf = [0u8; 32];
        seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
        let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

        let mut net = TestNet::new();

        for c in &mut net.cons {
            let proposal = rng.gen();
            let mut msgs = c.propose(proposal).unwrap();
            net.buffer.append(&mut msgs);
        }

        while !net.buffer.is_empty() {
            let rand_index = rng.gen_range(0..net.buffer.len());
            let rand_msg = &net.buffer.remove(rand_index);
            let mut msgs = Vec::new();

            for c in &mut net.cons {
                msgs.append(&mut match rand_msg {
                    Outgoing::Direct(id, bundle) => {
                        if id == &c.self_id {
                            c.process_bundle(bundle).unwrap()
                        } else {
                            Vec::new()
                        }
                    }
                    Outgoing::Gossip(bundle) => c.process_bundle(bundle).unwrap(),
                });
            }

            net.buffer.append(&mut msgs);
        }

        let mut decisions = HashMap::new();
        for c in &mut net.cons {
            if c.decided_proposer.is_some() {
                let value = c
                    .abba_map
                    .get(&c.decided_proposer.unwrap())
                    .unwrap()
                    .is_decided()
                    .unwrap();

                log::debug!(
                    "test for consensus {} finished on proposal {} with {value}",
                    c.self_id,
                    c.decided_proposer.unwrap(),
                );
                decisions.insert(c.self_id, (c.decided_proposer.unwrap(), value));
            }
        }

        // check if all consensus results are equal:
        assert_eq!(decisions.len(), net.cons.len());
        // https://sts10.github.io/2019/06/06/is-all-equal-function.html
        let first = decisions.iter().next().unwrap().1;
        assert!(decisions.iter().all(|(_, item)| item == first));
    }

    #[test]
    fn test_random_msg_mvba_accepts_messages_from_previous_proposer() {
        let seed: u128 = 31637883178971836821716406404683523;
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();

        let mut seed_buf = [0u8; 32];
        seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
        let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

        let mut net = TestNet::new();

        for c in &mut net.cons {
            let proposal = rng.gen();
            let mut msgs = c.propose(proposal).unwrap();
            net.buffer.append(&mut msgs);
        }

        while !net.buffer.is_empty() {
            let rand_index = rng.gen_range(0..net.buffer.len());
            let rand_msg = &net.buffer.remove(rand_index);
            let mut msgs = Vec::new();

            for c in &mut net.cons {
                msgs.append(&mut match rand_msg {
                    Outgoing::Direct(id, bundle) => {
                        if id == &c.self_id {
                            c.process_bundle(bundle).unwrap()
                        } else {
                            Vec::new()
                        }
                    }
                    Outgoing::Gossip(bundle) => c.process_bundle(bundle).unwrap(),
                });
            }

            net.buffer.append(&mut msgs);
        }

        let mut decisions = HashMap::new();
        for c in &mut net.cons {
            if c.decided_proposer.is_some() {
                let value = c
                    .abba_map
                    .get(&c.decided_proposer.unwrap())
                    .unwrap()
                    .is_decided()
                    .unwrap();

                log::debug!(
                    "test for consensus {} finished on proposal {} with {value}",
                    c.self_id,
                    c.decided_proposer.unwrap(),
                );
                decisions.insert(c.self_id, (c.decided_proposer.unwrap(), value));
            }
        }

        // check if all consensus results are equal:
        assert_eq!(decisions.len(), net.cons.len());
        // https://sts10.github.io/2019/06/06/is-all-equal-function.html
        let first = decisions.iter().next().unwrap().1;
        assert!(decisions.iter().all(|(_, item)| item == first));
    }

    #[test]
    fn test_proof() {
        let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
        let mut net = TestNet::new();

        for c in &mut net.cons {
            let proposal = rng.gen();
            let mut msgs = c.propose(proposal).unwrap();
            net.buffer.append(&mut msgs);
        }

        while !net.buffer.is_empty() {
            let rand_index = rng.gen_range(0..net.buffer.len());
            let rand_msg = &net.buffer.remove(rand_index);
            let mut msgs = Vec::new();

            for c in &mut net.cons {
                msgs.append(&mut match rand_msg {
                    Outgoing::Direct(id, bundle) => {
                        if id == &c.self_id {
                            c.process_bundle(bundle).unwrap()
                        } else {
                            Vec::new()
                        }
                    }
                    Outgoing::Gossip(bundle) => c.process_bundle(bundle).unwrap(),
                });
            }

            net.buffer.append(&mut msgs);
        }

        for c in &mut net.cons {
            if let Some(decision) = c.decided_proposal() {
                assert!(decision
                    .validate(&net.sks.public_keys().public_key())
                    .unwrap());
            }
        }
    }

    #[quickcheck]
    fn prop_random_msg_delivery(seed: u128) {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init();

        let mut seed_buf = [0u8; 32];
        seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
        let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

        let mut net = TestNet::new();

        for c in &mut net.cons {
            let proposal = rng.gen();
            let mut msgs = c.propose(proposal).unwrap();
            net.buffer.append(&mut msgs);
        }

        while !net.buffer.is_empty() {
            let rand_index = rng.gen_range(0..net.buffer.len());
            let rand_msg = &net.buffer.remove(rand_index);
            let mut msgs = Vec::new();

            for c in &mut net.cons {
                msgs.append(&mut match rand_msg {
                    Outgoing::Direct(id, bundle) => {
                        if id == &c.self_id {
                            c.process_bundle(bundle).unwrap()
                        } else {
                            Vec::new()
                        }
                    }
                    Outgoing::Gossip(bundle) => c.process_bundle(bundle).unwrap(),
                });
            }

            net.buffer.append(&mut msgs);
        }

        let mut decisions = HashMap::new();
        for c in &mut net.cons {
            if c.decided_proposer.is_some() {
                let value = c
                    .abba_map
                    .get(&c.decided_proposer.unwrap())
                    .unwrap()
                    .is_decided()
                    .unwrap();

                log::debug!(
                    "test for consensus {} finished on proposal {} with {value}",
                    c.self_id,
                    c.decided_proposer.unwrap(),
                );
                decisions.insert(c.self_id, (c.decided_proposer.unwrap(), value));
            }
        }

        // all decisions should be the same.
        assert_eq!(decisions.len(), net.cons.len());
        // https://sts10.github.io/2019/06/06/is-all-equal-function.html
        let first = decisions.iter().next().unwrap().1;
        assert!(decisions.iter().all(|(_, item)| item == first));
    }
}

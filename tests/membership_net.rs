use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::iter;

use blsttc::{SecretKeySet, SignatureShare};
use log::info;
use rand::prelude::{IteratorRandom, StdRng};
use rand::Rng;
use sn_consensus::{
    consensus::VoteResponse, Ballot, Decision, Error, Generation, Membership, NodeId, Reconfig,
    Result, SignedVote, Vote,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: NodeId,
    pub dest: NodeId,
    pub vote: SignedVote<Reconfig<u8>>,
}

#[derive(Default, Debug)]
pub struct Net {
    pub procs: Vec<Membership<u8>>,
    pub reconfigs_by_gen: BTreeMap<Generation, BTreeSet<Reconfig<u8>>>,
    pub members_at_gen: BTreeMap<Generation, BTreeSet<u8>>,
    pub packets: BTreeMap<NodeId, VecDeque<Packet>>,
    pub delivered_packets: Vec<Packet>,
    pub decisions: BTreeMap<Generation, Decision<Reconfig<u8>>>,
}

impl Net {
    pub fn with_procs(threshold: u8, n: u8, mut rng: &mut StdRng) -> Self {
        let elders_sk = SecretKeySet::random(threshold as usize, &mut rng);
        let procs = Vec::from_iter((1u8..(n + 1)).into_iter().map(|i| {
            Membership::from(
                (i, elders_sk.secret_key_share(i as u64)),
                elders_sk.public_keys(),
                n as usize,
            )
        }));
        Self {
            procs,
            ..Default::default()
        }
    }

    pub fn proc(&self, id: NodeId) -> Option<&Membership<u8>> {
        self.procs.iter().find(|p| p.id() == id)
    }

    pub fn proc_mut(&mut self, id: NodeId) -> Option<&mut Membership<u8>> {
        self.procs.iter_mut().find(|p| p.id() == id)
    }

    /// Pick a random public key from the set of procs
    pub fn pick_id(&self, rng: &mut StdRng) -> NodeId {
        self.procs.iter().choose(rng).unwrap().id()
    }

    /// Generate a randomized ballot
    pub fn gen_ballot(
        &self,
        recursion: u8,
        faulty: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> Ballot<Reconfig<u8>> {
        match rng.gen() || recursion == 0 {
            true => Ballot::Propose(match rng.gen() {
                true => Reconfig::Join(rng.gen()),
                false => Reconfig::Leave(rng.gen()),
            }),
            false => {
                let n_votes = rng.gen::<usize>() % self.procs.len().pow(2);
                let votes = BTreeSet::from_iter(
                    iter::repeat_with(|| self.gen_faulty_vote(recursion - 1, faulty, rng))
                        .take(n_votes),
                );
                match rng.gen() {
                    true => Ballot::Merge(votes),
                    false => {
                        let n_proposals = rng.gen::<usize>() % (self.procs.len() + 1);
                        let proposals: BTreeMap<Reconfig<u8>, (NodeId, SignatureShare)> =
                            std::iter::repeat_with(|| {
                                let prop = match rng.gen() {
                                    true => Reconfig::Join(rng.gen()),
                                    false => Reconfig::Leave(rng.gen()),
                                };
                                let sig = self
                                    .procs
                                    .iter()
                                    .choose(rng)
                                    .unwrap()
                                    .consensus
                                    .sign(&prop)?;
                                Ok((prop, (self.pick_id(rng), sig)))
                            })
                            .take(n_proposals)
                            .collect::<Result<_>>()
                            .unwrap();
                        Ballot::SuperMajority { votes, proposals }
                    }
                }
            }
        }
    }

    /// Generate a random faulty vote
    pub fn gen_faulty_vote(
        &self,
        recursion: u8,
        faulty_nodes: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> SignedVote<Reconfig<u8>> {
        let faulty_node = faulty_nodes
            .iter()
            .choose(rng)
            .and_then(|pk| self.proc(*pk))
            .unwrap();

        let vote = Vote {
            gen: rng.gen::<u64>() % 7,
            ballot: self.gen_ballot(recursion, faulty_nodes, rng),
            faults: Default::default(),
        };

        SignedVote {
            voter: self.pick_id(rng),
            ..faulty_node.sign_vote(vote).unwrap()
        }
    }

    /// Generate a faulty random packet
    pub fn gen_faulty_packet(
        &self,
        recursion: u8,
        faulty: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> Packet {
        Packet {
            source: *faulty.iter().choose(rng).unwrap(),
            dest: self.pick_id(rng),
            vote: self.gen_faulty_vote(recursion, faulty, rng),
        }
    }

    pub fn deliver_packet_from_source(&mut self, source: NodeId) -> Result<()> {
        let packet = match self.packets.get_mut(&source).map(|ps| ps.pop_front()) {
            Some(Some(p)) => p,
            _ => return Ok(()), // nothing to do
        };
        self.purge_empty_queues();

        // println!("delivering {:?}->{:?} {:?}", packet.source, dest, packet);

        self.delivered_packets.push(packet.clone());

        let source_elders = self.proc(source).unwrap().consensus.elders.clone();
        let dest_proc = match self.procs.iter_mut().find(|p| p.id() == packet.dest) {
            Some(proc) => proc,
            None => {
                return Ok(());
            }
        };

        info!("{} handling: {:?}", packet.dest, packet.vote);
        let packet_gen = packet.vote.vote.gen;
        let resp = dest_proc.handle_signed_vote(packet.vote);
        info!("resp from {}: {:?}", packet.dest, resp);
        match resp {
            Ok(VoteResponse::Broadcast(vote)) => {
                self.broadcast(packet.dest, vote);
            }
            Ok(VoteResponse::WaitingForMoreVotes) => {}
            Err(Error::NotElder) => {
                assert_ne!(dest_proc.consensus.elders, source_elders);
            }
            Err(Error::BadGeneration { requested_gen, gen }) => {
                assert!(requested_gen == 0 || requested_gen > gen + 1);
                assert_eq!(dest_proc.gen, gen);
            }
            Err(err) => return Err(err),
        }

        match self.proc(packet.dest) {
            Some(proc) => {
                let network_decision = self.decisions.get(&packet_gen);

                let proc_decision = proc
                    .consensus_at_gen(packet_gen)
                    .ok()
                    .and_then(|c| c.decision.clone());

                match (network_decision, proc_decision) {
                    (Some(net_d), Some(proc_d)) => {
                        assert_eq!(net_d.proposals, proc_d.proposals);
                    }
                    (None, Some(proc_d)) => {
                        assert!(proc_d.validate(&proc.consensus.elders).is_ok());
                        self.decisions.insert(packet_gen, proc_d);
                    }
                    (None | Some(_), None) => (),
                }

                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn enqueue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
        for packet in packets {
            self.packets
                .entry(packet.source)
                .or_default()
                .push_back(packet);
        }
    }

    pub fn broadcast_packets(
        &self,
        source: NodeId,
        vote: &SignedVote<Reconfig<u8>>,
    ) -> Vec<Packet> {
        Vec::from_iter(self.procs.iter().map(Membership::id).map(|dest| Packet {
            source,
            dest,
            vote: vote.clone(),
        }))
    }

    pub fn broadcast(&mut self, source: NodeId, vote: SignedVote<Reconfig<u8>>) {
        let packets = self.broadcast_packets(source, &vote);
        self.enqueue_packets(packets);
    }

    pub fn drain_queued_packets(&mut self) -> Result<()> {
        while let Some(source) = self.packets.keys().next().cloned() {
            self.deliver_packet_from_source(source)?;
            self.purge_empty_queues();
        }
        Ok(())
    }

    pub fn purge_empty_queues(&mut self) {
        self.packets = core::mem::take(&mut self.packets)
            .into_iter()
            .filter(|(_, queue)| !queue.is_empty())
            .collect();
    }

    pub fn enqueue_anti_entropy(&mut self, i: usize, j: usize) {
        let dest_generation = self.procs[i].gen;
        let dest = self.procs[i].id();
        let source = self.procs[j].id();

        self.enqueue_packets(
            self.procs[j]
                .anti_entropy(dest_generation)
                .unwrap()
                .into_iter()
                .map(|vote| Packet { source, dest, vote }),
        );
    }

    pub fn generate_msc(&self, name: &str) -> Result<()> {
        // See: http://www.mcternan.me.uk/mscgen/
        let mut msc = String::from(
            "
msc {\n
  hscale = \"2\";\n
",
        );
        let procs = self
            .procs
            .iter()
            .map(|p| p.id())
            .collect::<BTreeSet<_>>() // sort by actor id
            .into_iter()
            .map(|id| format!("{}", id))
            .collect::<Vec<_>>()
            .join(",");
        msc.push_str(&procs);
        msc.push_str(";\n");
        for packet in self.delivered_packets.iter() {
            msc.push_str(&format!(
                "{:?} -> {:?} [ label=\"{:?}\"];\n",
                packet.source, packet.dest, packet.vote
            ));
        }
        msc.push_str("}\n");

        let mut msc_file = File::create(name)?;
        msc_file.write_all(msc.as_bytes())?;
        Ok(())
    }
}

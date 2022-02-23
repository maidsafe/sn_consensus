use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::iter;

use blsttc::{SecretKeySet, SignatureShare};
use rand::prelude::{IteratorRandom, StdRng};
use rand::Rng;

use sn_membership::{Ballot, Error, Handover, NodeId, Result, SignedVote, Vote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: NodeId,
    pub dest: NodeId,
    pub vote: SignedVote<u8>,
}

#[derive(Default, Debug)]
pub struct Net {
    pub procs: Vec<Handover<u8>>,
    pub proposals: BTreeSet<u8>,
    pub packets: BTreeMap<NodeId, VecDeque<Packet>>,
    pub delivered_packets: Vec<Packet>,
}

impl Net {
    pub fn with_procs(threshold: usize, n: usize, mut rng: &mut StdRng) -> Self {
        let elders_sk = SecretKeySet::random(threshold, &mut rng);

        let procs = Vec::from_iter((1..=n).into_iter().map(|i| {
            Handover::from(
                (i as u8, elders_sk.secret_key_share(i)),
                elders_sk.public_keys(),
                n,
                0,
            )
        }));
        Self {
            procs,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn proc(&self, id: NodeId) -> Option<&Handover<u8>> {
        self.procs.iter().find(|p| p.id() == id)
    }

    pub fn consensus_value(&self, proc: usize) -> Option<u8> {
        self.procs[proc]
            .consensus
            .decision
            .as_ref()
            .and_then(|decision| self.procs[proc].resolve_votes(&decision.proposals).cloned())
    }

    /// Pick a random public key from the set of procs
    #[allow(dead_code)]
    pub fn pick_id(&self, rng: &mut StdRng) -> NodeId {
        self.procs.iter().choose(rng).unwrap().id()
    }

    /// Generate a randomized ballot
    #[allow(dead_code)]
    pub fn gen_ballot(
        &self,
        recursion: u8,
        faulty: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> Ballot<u8> {
        match rng.gen() || recursion == 0 {
            true => Ballot::Propose(rng.gen()),
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
                        let proposals: BTreeMap<u8, (NodeId, SignatureShare)> =
                            std::iter::repeat_with(|| {
                                let prop = rng.gen();
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
    #[allow(dead_code)]
    pub fn gen_faulty_vote(
        &self,
        recursion: u8,
        faulty_nodes: &BTreeSet<NodeId>,
        rng: &mut StdRng,
    ) -> SignedVote<u8> {
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
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn drop_packet_from_source(&mut self, source: NodeId) {
        self.packets.get_mut(&source).map(VecDeque::pop_front);
    }

    pub fn deliver_packet_from_source(&mut self, source: NodeId) -> Result<()> {
        let packet = match self.packets.get_mut(&source).map(|ps| ps.pop_front()) {
            Some(Some(p)) => p,
            _ => return Ok(()), // nothing to do
        };
        self.purge_empty_queues();

        self.delivered_packets.push(packet.clone());

        let source_elders = self.proc(source).unwrap().consensus.elders.clone();
        let dest_proc = match self.procs.iter_mut().find(|p| p.id() == packet.dest) {
            Some(proc) => proc,
            None => {
                // println!("[NET] destination proc does not exist, dropping packet");
                return Ok(());
            }
        };

        let resp = dest_proc.handle_signed_vote(packet.vote);
        // println!("[NET] resp: {:?}", resp);
        match resp {
            Ok(Some(vote)) => {
                let dest_actor = dest_proc.id();
                self.broadcast(dest_actor, vote);
            }
            Ok(None) => {}
            Err(Error::NotElder) => {
                assert_ne!(dest_proc.consensus.elders, source_elders);
            }
            Err(Error::VoteWithInvalidUniqueSectionId { vote_gen, gen }) => {
                assert!(vote_gen != gen);
                assert_eq!(dest_proc.gen, gen);
            }
            Err(err) => return Err(err),
        }

        Ok(())
    }

    pub fn enqueue_packets(&mut self, packets: impl IntoIterator<Item = Packet>) {
        for packet in packets {
            self.packets
                .entry(packet.source)
                .or_default()
                .push_back(packet)
        }
    }

    pub fn broadcast(&mut self, source: NodeId, vote: SignedVote<u8>) {
        let packets = Vec::from_iter(self.procs.iter().map(Handover::id).map(|dest| Packet {
            source,
            dest,
            vote: vote.clone(),
        }));
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
        let dest = self.procs[i].id();
        let source = self.procs[j].id();

        self.enqueue_packets(self.procs[j].anti_entropy().into_iter().map(|vote| Packet {
            source,
            dest,
            vote,
        }));
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
            .map(|id| format!("{:?}", id))
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

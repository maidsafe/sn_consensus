use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::Write;
use std::iter;

use blsttc::PublicKeyShare;
use rand::prelude::{IteratorRandom, StdRng};
use rand::Rng;
use serde::{Deserialize, Serialize};

use sn_membership::{Ballot, Error, Handover, Result, SignedVote, Vote};

// dummy proposal for tests
#[derive(Clone, Debug, Eq, PartialOrd, Ord, PartialEq, Serialize, Deserialize)]
pub struct DummyProposal(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub source: PublicKeyShare,
    pub dest: PublicKeyShare,
    pub vote: SignedVote<DummyProposal>,
}

#[derive(Default, Debug)]
pub struct Net {
    pub procs: Vec<Handover<DummyProposal>>,
    pub proposals: BTreeSet<DummyProposal>,
    pub packets: BTreeMap<PublicKeyShare, VecDeque<Packet>>,
    pub delivered_packets: Vec<Packet>,
}

impl Net {
    pub fn with_procs(n: usize, mut rng: &mut StdRng) -> Self {
        let mut procs = Vec::from_iter(iter::repeat_with(|| Handover::random(&mut rng, 0)).take(n));
        procs.sort_by_key(|p| p.public_key_share());
        Self {
            procs,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn proc(&self, public_key_share: PublicKeyShare) -> Option<&Handover<DummyProposal>> {
        self.procs
            .iter()
            .find(|p| p.public_key_share() == public_key_share)
    }

    pub fn consensus_value(&self, proc: usize) -> Option<DummyProposal> {
        let all_votes = self.procs[proc]
            .consensus
            .votes
            .iter()
            .map(|(_voter, vote)| vote)
            .cloned()
            .collect();
        self.procs[proc].resolve_votes(&all_votes)
    }

    /// Pick a random public key from the set of procs
    #[allow(dead_code)]
    pub fn gen_public_key(&self, rng: &mut StdRng) -> PublicKeyShare {
        self.procs
            .iter()
            .choose(rng)
            .map(Handover::public_key_share)
            .unwrap()
    }

    /// Generate a randomized ballot
    #[allow(dead_code)]
    pub fn gen_ballot(
        &self,
        recursion: u8,
        faulty: &BTreeSet<PublicKeyShare>,
        rng: &mut StdRng,
    ) -> Ballot<DummyProposal> {
        match rng.gen() || recursion == 0 {
            true => Ballot::Propose(match rng.gen() {
                true => DummyProposal(1),
                false => DummyProposal(0),
            }),
            false => {
                let n_votes = rng.gen::<usize>() % self.procs.len().pow(2);
                let random_votes = BTreeSet::from_iter(
                    iter::repeat_with(|| self.gen_faulty_vote(recursion - 1, faulty, rng))
                        .take(n_votes),
                );
                match rng.gen() {
                    true => Ballot::Merge(random_votes),
                    false => Ballot::SuperMajority(random_votes),
                }
            }
        }
    }

    /// Generate a random faulty vote
    #[allow(dead_code)]
    pub fn gen_faulty_vote(
        &self,
        recursion: u8,
        faulty_nodes: &BTreeSet<PublicKeyShare>,
        rng: &mut StdRng,
    ) -> SignedVote<DummyProposal> {
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

        let mut signed_vote = faulty_node.sign_vote(vote).unwrap();
        let node_to_impersonate = self.procs.iter().choose(rng).unwrap().public_key_share();
        signed_vote.voter = node_to_impersonate;
        signed_vote
    }

    /// Generate a faulty random packet
    #[allow(dead_code)]
    pub fn gen_faulty_packet(
        &self,
        recursion: u8,
        faulty: &BTreeSet<PublicKeyShare>,
        rng: &mut StdRng,
    ) -> Packet {
        Packet {
            source: *faulty.iter().choose(rng).unwrap(),
            vote: self.gen_faulty_vote(recursion, faulty, rng),
            dest: self.gen_public_key(rng),
        }
    }

    #[allow(dead_code)]
    pub fn drop_packet_from_source(&mut self, source: PublicKeyShare) {
        self.packets.get_mut(&source).map(VecDeque::pop_front);
    }

    pub fn deliver_packet_from_source(&mut self, source: PublicKeyShare) -> Result<()> {
        let packet = match self.packets.get_mut(&source).map(|ps| ps.pop_front()) {
            Some(Some(p)) => p,
            _ => return Ok(()), // nothing to do
        };
        self.purge_empty_queues();

        self.delivered_packets.push(packet.clone());

        let dest = packet.dest;
        let dest_proc = match self.procs.iter_mut().find(|p| p.public_key_share() == dest) {
            Some(proc) => proc,
            None => {
                // println!("[NET] destination proc does not exist, dropping packet");
                return Ok(());
            }
        };

        let dest_elders = dest_proc.consensus.elders.clone();

        let resp = dest_proc.handle_signed_vote(packet.vote);
        // println!("[NET] resp: {:?}", resp);
        match resp {
            Ok(Some(vote)) => {
                let dest_actor = dest_proc.public_key_share();
                self.broadcast(dest_actor, vote);
            }
            Ok(None) => {}
            Err(Error::NotElder {
                public_key: voter,
                elders,
            }) => {
                assert_eq!(elders, dest_elders);
                assert!(
                    !dest_elders.contains(&voter),
                    "{:?} should not be in {:?}",
                    source,
                    dest_elders
                );
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

    pub fn broadcast(&mut self, source: PublicKeyShare, vote: SignedVote<DummyProposal>) {
        let packets = Vec::from_iter(self.procs.iter().map(Handover::public_key_share).map(
            |dest| Packet {
                source,
                dest,
                vote: vote.clone(),
            },
        ));
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
        let dest = self.procs[i].public_key_share();
        let source = self.procs[j].public_key_share();

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
            .map(|p| p.public_key_share())
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

        // Replace process identifiers with friendlier numbers
        // 1, 2, 3 ... instead of i:3b2, i:7def, ...
        for (idx, proc_id) in self
            .procs
            .iter()
            .map(Handover::public_key_share)
            .enumerate()
        {
            let proc_id_as_str = format!("{:?}", proc_id);
            msc = msc.replace(&proc_id_as_str, &format!("{}", idx + 1));
        }

        let mut msc_file = File::create(name)?;
        msc_file.write_all(msc.as_bytes())?;
        Ok(())
    }
}

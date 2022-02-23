use blsttc::{SecretKeySet, SecretKeyShare};
use eyre::eyre;
use membership_net::{Net, Packet};
use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng, SeedableRng,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
};

mod membership_net;

use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;
use sn_membership::{Ballot, Error, Generation, Membership, Reconfig, Result, SignedVote, Vote};

#[test]
fn test_membership_reject_changing_reconfig_when_one_is_in_progress() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );
    proc.propose(Reconfig::Join(rng.gen()))?;
    assert!(matches!(
        proc.propose(Reconfig::Join(rng.gen())),
        Err(Error::AttemptedFaultyProposal)
    ));
    Ok(())
}

#[test]
fn test_membership_reject_vote_from_non_member() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut p0 = Membership::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut p1 = Membership::<u8>::from(
        (1, elders_sk.secret_key_share(1)),
        elders_sk.public_keys(),
        1,
    );

    let vote = p1.propose(Reconfig::Join(rng.gen()))?;
    let resp = p0.handle_signed_vote(vote);
    assert!(matches!(resp, Err(Error::InvalidElderSignature)));
    Ok(())
}

#[test]
fn test_membership_reject_join_if_actor_is_already_a_member() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );
    proc.force_join(111);

    assert!(matches!(
        proc.propose(Reconfig::Join(111)),
        Err(Error::JoinRequestForExistingMember { .. })
    ));
}

#[test]
fn test_membership_reject_leave_if_actor_is_not_a_member() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );
    proc.force_join(111);

    assert!(matches!(
        proc.propose(Reconfig::Leave(222)),
        Err(Error::LeaveRequestForNonMember { .. })
    ));
}

#[test]
fn test_membership_handle_vote_rejects_packet_from_previous_gen() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(1, 2, &mut rng);
    let a_0 = net.procs[0].id();
    let a_1 = net.procs[1].id();

    let vote = net.procs[0].propose(Reconfig::Join(111))?;
    let packets = net
        .procs
        .iter()
        .map(Membership::id)
        .map(|dest| Packet {
            source: a_0,
            dest,
            vote: vote.clone(),
        })
        .collect::<Vec<_>>();

    let stale_vote = net.procs[1].propose(Reconfig::Join(222))?;

    let stale_packets = net
        .procs
        .iter()
        .map(Membership::id)
        .map(|dest| Packet {
            source: a_1,
            dest,
            vote: stale_vote.clone(),
        })
        .collect::<Vec<_>>();

    net.procs[1].pending_gen = 0;
    net.procs[1].consensus.votes = Default::default();

    assert_eq!(packets.len(), 2); // two members in the network
    assert_eq!(stale_packets.len(), 2);

    net.enqueue_packets(packets);
    net.drain_queued_packets()?;

    for packet in stale_packets {
        assert!(matches!(
            net.procs[0].handle_signed_vote(packet.vote),
            Err(Error::VoteNotForNextGeneration {
                vote_gen: 1,
                gen: 1,
                pending_gen: 1,
            })
        ));
    }

    Ok(())
}

#[test]
fn test_membership_reject_votes_with_invalid_signatures() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );
    let ballot = Ballot::Propose(Reconfig::Join(rng.gen()));
    let gen = proc.gen + 1;
    let vote = Vote {
        gen,
        ballot,
        faults: Default::default(),
    };
    let bytes = vote.to_bytes()?;
    let voter = 0;
    let sig = rng.gen::<SecretKeyShare>().sign(&bytes);
    let resp = proc.handle_signed_vote(SignedVote { vote, voter, sig });
    assert!(matches!(resp, Err(Error::InvalidElderSignature)));
    Ok(())
}

#[test]
fn test_membership_split_vote() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(((nprocs + 1) * 2 / 3).min(nprocs - 1), nprocs, &mut rng);

        for i in 0..net.procs.len() {
            let a_i = net.procs[i].id();
            let vote = net.procs[i].propose(Reconfig::Join(i as u8))?;
            net.broadcast(a_i, vote);
        }

        net.drain_queued_packets()?;
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i as usize, j as usize);
            }
        }
        net.drain_queued_packets()?;

        assert!(net.packets.is_empty());

        net.generate_msc(&format!("split_vote_{}.msc", nprocs))?;

        for i in 0..nprocs {
            assert_eq!(net.procs[i as usize].gen, net.procs[i as usize].pending_gen);
        }
        let proc0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc0_gen)?;

        for i in 0..nprocs {
            let proc_i_gen = net.procs[i as usize].gen;
            assert_eq!(proc_i_gen, proc0_gen);
            assert_eq!(net.procs[i as usize].members(proc_i_gen)?, expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_membership_round_robin_split_vote() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(((nprocs + 1) * 2 / 3).min(nprocs - 1), nprocs, &mut rng);

        for i in 0..net.procs.len() {
            let a_i = net.procs[i].id();
            let vote = net.procs[i].propose(Reconfig::Join(i as u8))?;
            net.broadcast(a_i, vote);
        }

        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].id())?;
            }
        }

        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        net.generate_msc(&format!("round_robin_split_vote_{}.msc", nprocs))?;

        let proc_0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc_0_gen)?;
        assert_eq!(expected_members, BTreeSet::from_iter(0..(nprocs as u8)));

        for i in 0..nprocs {
            let gen = net.procs[i as usize].gen;
            assert_eq!(gen, proc_0_gen);
            assert_eq!(net.procs[i as usize].members(gen)?, expected_members);
        }
    }
    Ok(())
}

#[test]
fn test_membership_onboarding_across_many_generations() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(1, 2, &mut rng);
    let p0 = net.procs[0].id();
    let p1 = net.procs[1].id();

    let vote = net.procs[0].propose(Reconfig::Join(1)).unwrap();
    net.broadcast(p0, vote);
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    assert!(net.packets.is_empty());
    let vote = net.procs[0].propose(Reconfig::Join(2)).unwrap();
    net.broadcast(p0, vote);
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("onboarding_across_many_generations.msc")
        .unwrap();

    // All procs should be at the same generation
    assert!(net.procs.iter().all(|p| p.gen == net.procs[0].gen));

    // All procs should agree on the final members
    let current_members = net.procs[0].members(net.procs[0].gen).unwrap();
    for proc in net.procs.iter() {
        assert_eq!(current_members, proc.members(proc.gen)?);
    }
    assert!(current_members.contains(&2));
    Ok(())
}

#[test]
fn test_membership_simple_proposal() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, 3, &mut rng);

    let p0 = net.procs[0].id();
    let vote = net.procs[0].propose(Reconfig::Join(0)).unwrap();
    net.broadcast(p0, vote);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("simple_join.msc")?;

    for p in net.procs {
        assert_eq!(p.members(1).unwrap(), BTreeSet::from_iter([0]));
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum Instruction {
    RequestJoin(u8, usize),
    RequestLeave(u8, usize),
    DeliverPacketFromSource(usize),
    AntiEntropy(Generation, usize, usize),
}
impl Arbitrary for Instruction {
    fn arbitrary(g: &mut Gen) -> Self {
        let member = u8::arbitrary(g) % 21;
        let elder = usize::arbitrary(g) % 7;
        let other_elder = usize::arbitrary(g) % 7;
        let gen: Generation = Generation::arbitrary(g) % 20;

        match u8::arbitrary(g) % 4 {
            0 => Instruction::RequestJoin(member, elder),
            1 => Instruction::RequestLeave(member, elder),
            2 => Instruction::DeliverPacketFromSource(elder),
            3 => Instruction::AntiEntropy(gen, elder, other_elder),
            i => panic!("unexpected instruction index {}", i),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut shrunk_ops = Vec::new();
        match self.clone() {
            Instruction::RequestJoin(member, elder) => {
                if member > 0 && elder > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(member - 1, elder - 1));
                }
                if member > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(member - 1, elder));
                }
                if elder > 0 {
                    shrunk_ops.push(Instruction::RequestJoin(member, elder - 1));
                }
            }
            Instruction::RequestLeave(member, elder) => {
                if member > 0 && elder > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(member - 1, elder - 1));
                }
                if member > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(member - 1, elder));
                }
                if elder > 0 {
                    shrunk_ops.push(Instruction::RequestLeave(member, elder - 1));
                }
            }
            Instruction::DeliverPacketFromSource(elder) => {
                if elder > 0 {
                    shrunk_ops.push(Instruction::DeliverPacketFromSource(elder - 1));
                }
            }
            Instruction::AntiEntropy(gen, elder, other_elder) => {
                if elder > 0 && other_elder > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, elder - 1, other_elder - 1));
                }
                if elder > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, elder - 1, other_elder));
                }
                if other_elder > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen, elder, other_elder - 1));
                }
                if gen > 0 {
                    shrunk_ops.push(Instruction::AntiEntropy(gen - 1, elder, other_elder));
                }
            }
        }

        Box::new(shrunk_ops.into_iter())
    }
}

#[test]
fn test_membership_interpreter_qc1() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(1, 2, &mut rng);
    let p0 = net.procs[0].id();

    let reconfig = Reconfig::Join(1);
    let q = &mut net.procs[0];
    net.reconfigs_by_gen
        .entry(q.pending_gen)
        .or_default()
        .insert(reconfig);
    let vote = q.propose(reconfig).unwrap();
    net.broadcast(p0, vote);

    net.enqueue_anti_entropy(1, 0);
    net.enqueue_anti_entropy(1, 0);

    for _ in 0..3 {
        net.drain_queued_packets().unwrap();
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }
    assert!(net.packets.is_empty());

    for p in net.procs.iter() {
        assert_eq!(p.members(p.gen)?, net.procs[0].members(p.gen)?);
    }
    Ok(())
}

#[test]
fn test_membership_interpreter_qc2() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, 3, &mut rng);
    let p0 = net.procs[0].id();

    let vote = net.procs[0].propose(Reconfig::Join(1))?;
    net.broadcast(p0, vote);
    net.drain_queued_packets()?;
    let vote = net.procs[0].propose(Reconfig::Join(2))?;
    net.broadcast(p0, vote);
    net.drain_queued_packets()?;

    net.generate_msc("interpreter_qc2.msc")?;

    assert!(net.packets.is_empty());

    // We should have no more pending votes.
    let expected_members = net.procs[0].members(net.procs[0].pending_gen)?;
    for p in net.procs.iter() {
        assert_eq!(p.gen, p.pending_gen);
        assert_eq!(p.consensus.votes, Default::default());
        assert_eq!(p.members(p.gen)?, expected_members);
    }

    Ok(())
}

#[test]
fn test_membership_interpreter_qc3() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, 4, &mut rng);

    let p0 = net.procs[0].id();
    // 1 requests to join genesis
    let reconfig = Reconfig::Join(0);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_vote = net.procs[0].propose(reconfig).unwrap();
    net.broadcast(p0, propose_vote);

    net.drain_queued_packets().unwrap();

    let reconfig = Reconfig::Leave(0);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_vote = net.procs[0].propose(reconfig).unwrap();
    net.broadcast(p0, propose_vote);

    let q_actor = net.procs[2].id();
    let anti_entropy_packets = net.procs[0]
        .anti_entropy(0)
        .unwrap()
        .into_iter()
        .map(|vote| Packet {
            source: p0,
            dest: q_actor,
            vote,
        });

    net.enqueue_packets(anti_entropy_packets);
    net.drain_queued_packets().unwrap();

    for i in 0..net.procs.len() {
        for j in 0..net.procs.len() {
            net.enqueue_anti_entropy(i, j);
        }
    }

    let res = net.drain_queued_packets();

    net.generate_msc("test_membership_interpreter_qc3.msc")
        .unwrap();

    assert!(res.is_ok());
}

#[test]
fn test_membership_procs_refuse_to_propose_competing_votes() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
    );

    proc.propose(Reconfig::Join(0_u8))?;

    // Proposing a second join reconfig for a different member should fail
    let reconfig = Reconfig::Join(1_u8);
    assert!(matches!(
        proc.propose(reconfig),
        Err(Error::AttemptedFaultyProposal)
    ));
    assert!(!proc
        .consensus
        .votes
        .get(&proc.id())
        .unwrap()
        .supersedes(&proc.sign_vote(Vote {
            ballot: Ballot::Propose(reconfig),
            gen: proc.gen,
            faults: proc.consensus.faults(),
        })?));

    Ok(())
}

#[test]
fn test_membership_validate_reconfig_rejects_when_members_at_capacity() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Membership::<u8>::from(
        (0, elders_sk.secret_key_share(0usize)),
        elders_sk.public_keys(),
        1,
    );

    for m in 0..7 {
        proc.force_join(m);
    }

    assert!(matches!(
        proc.validate_reconfig(Reconfig::Join(7)),
        Err(Error::MembersAtCapacity)
    ));

    Ok(())
}

#[test]
fn test_membership_bft_consensus_qc1() -> Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, 6, &mut rng);
    let faulty = BTreeSet::from_iter([net.procs[1].id(), net.procs[5].id()]);

    // send a randomized packet
    let packet = Packet {
        source: net.procs[1].id(),
        dest: net.procs[0].id(),
        vote: net.procs[1].sign_vote(Vote {
            gen: 1,
            ballot: Ballot::Propose(Reconfig::Join(240)),
            faults: Default::default(),
        })?,
    };
    net.enqueue_packets(vec![packet]);
    let packet = Packet {
        source: net.procs[1].id(),
        dest: net.procs[0].id(),
        vote: SignedVote {
            voter: net.procs[1].id(),
            ..net.procs[5].sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(Reconfig::Join(115)),
                faults: Default::default(),
            })?
        },
    };
    net.enqueue_packets(vec![packet]);

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }
    net.generate_msc("bft_consensus_qc1.msc")?;

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| !faulty.contains(&p.id())));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.gen, p.pending_gen);
        assert_eq!(p.consensus.votes, BTreeMap::default());
    }

    // BFT AGREEMENT PROPERTY: all honest procs have decided on the same values
    let reference_proc = &honest_procs[0];
    for p in honest_procs.iter() {
        assert_eq!(reference_proc.gen, p.gen);
        for g in 0..=reference_proc.gen {
            assert_eq!(reference_proc.members(g).unwrap(), p.members(g).unwrap())
        }
    }

    Ok(())
}

#[test]
fn test_membership_bft_consensus_qc2() -> Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, 5, &mut rng);
    let faulty = BTreeSet::from_iter([net.procs[0].id()]);
    // node takes honest action
    let vote = net.procs[1].propose(Reconfig::Join(0)).unwrap();
    net.broadcast(net.procs[1].id(), vote);

    let packet = Packet {
        source: net.procs[0].id(),
        dest: net.procs[1].id(),
        vote: net.procs[0]
            .sign_vote(Vote {
                gen: 1,
                ballot: Ballot::Propose(Reconfig::Join(1)),
                faults: Default::default(),
            })
            .unwrap(),
    };
    net.enqueue_packets(vec![packet]);

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }

    net.generate_msc("test_bft_consensus_qc2.msc")?;

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| !faulty.contains(&p.id())));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.consensus.votes, Default::default());
        assert_eq!(p.gen, p.pending_gen);
    }

    // BFT AGREEMENT PROPERTY: all honest procs have decided on the same values
    let reference_proc = &honest_procs[0];
    for p in honest_procs.iter() {
        assert_eq!(reference_proc.gen, p.gen);
        for g in 0..=reference_proc.gen {
            assert_eq!(reference_proc.members(g).unwrap(), p.members(g).unwrap())
        }
    }

    assert_eq!(reference_proc.members(1).unwrap(), BTreeSet::from_iter([0]));

    Ok(())
}

#[quickcheck]
fn prop_interpreter(n: u8, instructions: Vec<Instruction>, seed: u128) -> eyre::Result<TestResult> {
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    fn super_majority(m: usize, n: usize) -> bool {
        3 * m > 2 * n
    }

    let n = n.min(7) as usize;
    if n == 0 || instructions.len() > 12 {
        return Ok(TestResult::discard());
    }

    let mut net = Net::with_procs(((n as u8 + 1) * 2 / 3).min(n as u8 - 1), n as u8, &mut rng);

    for instruction in instructions {
        match instruction {
            Instruction::RequestJoin(p, q_idx) => {
                let reconfig = Reconfig::Join(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_id = q.id();
                match q.propose(reconfig) {
                    Ok(vote) => {
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.broadcast(q_id, vote);
                    }
                    Err(Error::JoinRequestForExistingMember { .. }) => {
                        assert!(q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::AttemptedFaultyProposal) => {
                        // This proc has already committed to a vote this round

                        // This proc has already committed to a vote
                        assert!(!q.consensus.votes.get(&q.id()).unwrap().supersedes(
                            &q.sign_vote(Vote {
                                ballot: Ballot::Propose(reconfig),
                                gen: q.gen,
                                faults: q.consensus.faults(),
                            })?
                        ));
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Failure to reconfig is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::RequestLeave(p, q_idx) => {
                let reconfig = Reconfig::Leave(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_id = q.id();
                match q.propose(reconfig) {
                    Ok(vote) => {
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.broadcast(q_id, vote);
                    }
                    Err(Error::LeaveRequestForNonMember { .. }) => {
                        assert!(!q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::AttemptedFaultyProposal) => {
                        // This proc has already committed to a vote
                        assert!(!q.consensus.votes.get(&q.id()).unwrap().supersedes(
                            &q.sign_vote(Vote {
                                ballot: Ballot::Propose(reconfig),
                                gen: q.gen,
                                faults: q.consensus.faults(),
                            })
                            .unwrap()
                        ))
                    }
                    Err(err) => {
                        // invalid request.
                        panic!("Leave Failure is not handled yet: {:?}", err);
                    }
                }
            }
            Instruction::DeliverPacketFromSource(source_idx) => {
                // deliver packet
                let source = net.procs[source_idx.min(n - 1)].id();
                net.deliver_packet_from_source(source)?;
            }
            Instruction::AntiEntropy(gen, p_idx, q_idx) => {
                let p = &net.procs[p_idx.min(n - 1)];
                let dest = net.procs[q_idx.min(n - 1)].id();
                let source = p.id();
                let anti_entropy_packets =
                    p.anti_entropy(gen)?
                        .into_iter()
                        .map(|vote| Packet { source, dest, vote });
                net.enqueue_packets(anti_entropy_packets);
            }
        }
    }

    // 3 rounds of anti-entropy will get everyone in sync
    for _ in 0..3 {
        net.drain_queued_packets()?;
        for i in 0..net.procs.len() {
            for j in 0..net.procs.len() {
                net.enqueue_anti_entropy(i, j);
            }
        }
    }
    assert!(
        net.packets.is_empty(),
        "We should have no more pending packets"
    );

    // We should have no more pending votes.
    for p in net.procs.iter() {
        assert_eq!(p.consensus.votes, Default::default());
    }

    let mut procs_by_gen: BTreeMap<Generation, Vec<Membership<u8>>> = Default::default();

    for proc in net.procs {
        procs_by_gen.entry(proc.gen).or_default().push(proc);
    }

    let max_gen = procs_by_gen
        .keys()
        .last()
        .ok_or_else(|| eyre!("No generations logged"))?;

    // And procs at each generation should have agreement on members
    for (gen, procs) in procs_by_gen.iter() {
        let mut proc_iter = procs.iter();
        let first = proc_iter.next().ok_or(Error::NoMembers)?;
        if *gen > 0 {
            // TODO: remove this gen > 0 constraint
            assert_eq!(first.members(first.gen)?, net.members_at_gen[gen]);
        }
        for proc in proc_iter {
            assert_eq!(
                first.members(first.gen)?,
                proc.members(proc.gen)?,
                "gen: {}",
                gen
            );
        }
    }

    // TODO: everyone that a proc at G considers a member is also at generation G

    for (gen, reconfigs) in net.reconfigs_by_gen.iter() {
        let members_at_prev_gen = &net.members_at_gen[&(gen - 1)];
        let members_at_curr_gen = net.members_at_gen[gen].clone();
        let mut reconfigs_applied: BTreeSet<&Reconfig<u8>> = Default::default();
        for reconfig in reconfigs {
            match reconfig {
                Reconfig::Join(m) => {
                    assert!(!members_at_prev_gen.contains(m));
                    if members_at_curr_gen.contains(m) {
                        reconfigs_applied.insert(reconfig);
                    }
                }
                Reconfig::Leave(m) => {
                    assert!(members_at_prev_gen.contains(m));
                    if !members_at_curr_gen.contains(m) {
                        reconfigs_applied.insert(reconfig);
                    }
                }
            }
        }

        assert_ne!(reconfigs_applied, Default::default());
    }

    let proc_at_max_gen = procs_by_gen[max_gen].get(0).ok_or(Error::NoMembers)?;
    assert!(super_majority(
        procs_by_gen[max_gen].len(),
        proc_at_max_gen.consensus.n_elders
    ));

    Ok(TestResult::passed())
}

#[quickcheck]
fn prop_validate_reconfig(
    join_or_leave: bool,
    member: u8,
    initial_members: BTreeSet<u8>,
    threshold: u8,
    seed: u128,
) -> Result<TestResult> {
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    if threshold > 5 {
        return Ok(TestResult::discard());
    }

    let elders_sk = SecretKeySet::random(threshold as usize, &mut rng);
    let mut proc = Membership::<u8>::from(
        (1, elders_sk.secret_key_share(1usize)),
        elders_sk.public_keys(),
        (3 * threshold / 2) as usize,
    );

    for m in initial_members.iter().copied() {
        proc.force_join(m);
    }

    let reconfig = match join_or_leave {
        true => Reconfig::Join(member),
        false => Reconfig::Leave(member),
    };

    let valid_res = proc.validate_reconfig(reconfig);
    let proc_members = proc.members(proc.gen)?;
    match reconfig {
        Reconfig::Join(member) => {
            if proc_members.contains(&member) {
                assert!(matches!(
                    valid_res,
                    Err(Error::JoinRequestForExistingMember { .. })
                ));
            } else if initial_members.len() >= 7 {
                assert!(matches!(valid_res, Err(Error::MembersAtCapacity)));
            } else {
                assert!(valid_res.is_ok());
            }
        }
        Reconfig::Leave(member) => {
            if proc_members.contains(&member) {
                assert!(valid_res.is_ok());
            } else {
                assert!(matches!(
                    valid_res,
                    Err(Error::LeaveRequestForNonMember { .. })
                ));
            }
        }
    };

    Ok(TestResult::passed())
}

#[quickcheck]
fn prop_bft_consensus(
    recursion_limit: u8,
    n: u8,
    faulty: Vec<u8>,
    seed: u128,
) -> Result<TestResult> {
    let n = n % 6 + 1;
    let recursion_limit = recursion_limit % (n / 2).max(1);
    let faulty = BTreeSet::from_iter(
        faulty
            .into_iter()
            .map(|p| p % n)
            .filter(|p| p != &0) // genesis can not be faulty
            .take((n / 3u8).saturating_sub(1) as usize),
    );
    // All non-faulty nodes eventually decide on a reconfig

    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

    let mut net = Net::with_procs(((n + 1) * 2 / 3).min(n - 1), n, &mut rng);

    let faulty = BTreeSet::from_iter(faulty.into_iter().map(|idx| net.procs[idx as usize].id()));

    let n_actions = rng.gen::<u8>() % 4;

    for _ in 0..n_actions {
        match rng.gen::<u8>() % 3 {
            0 if !faulty.is_empty() => {
                match rng.gen::<bool>() {
                    true => {
                        // send a randomized packet
                        let packet = net.gen_faulty_packet(recursion_limit, &faulty, &mut rng);
                        net.enqueue_packets(vec![packet]);
                    }
                    false => {
                        // drop a random packet
                        let source = net.pick_id(&mut rng);
                        net.drop_packet_from_source(source);
                    }
                };
            }
            1 => {
                // node takes honest action
                let proc = if let Some(proc) = net
                    .procs
                    .iter_mut()
                    .filter(|p| !faulty.contains(&p.id())) // filter out faulty nodes
                    .filter(|p| p.gen == p.pending_gen) // filter out nodes who have already voted this round
                    .choose(&mut rng)
                {
                    proc
                } else {
                    // No honest node can take an action
                    continue;
                };

                let source = proc.id();
                let proc_members = proc.members(proc.gen).unwrap();

                let reconfig = match rng.gen::<bool>() || proc_members.is_empty() {
                    true => Reconfig::Join(
                        iter::repeat_with(|| rng.gen::<u8>())
                            .find(|m| !proc.members(proc.gen).unwrap().contains(m))
                            .unwrap(),
                    ),
                    false => Reconfig::Leave(proc_members.into_iter().choose(&mut rng).unwrap()),
                };

                let vote = proc.propose(reconfig).unwrap();
                net.broadcast(source, vote);
            }
            _ => {
                // Network delivers a packet
                let source = net.pick_id(&mut rng);
                let _ = net.deliver_packet_from_source(source);
            }
        };
    }

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| !faulty.contains(&p.id())));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.consensus.votes, Default::default());
        assert_eq!(p.gen, p.pending_gen);
    }

    // BFT AGREEMENT PROPERTY: all honest procs have decided on the same values
    let reference_proc = &honest_procs[0];
    for p in honest_procs.iter() {
        assert_eq!(reference_proc.gen, p.gen);
        for g in 0..=reference_proc.gen {
            assert_eq!(reference_proc.members(g).unwrap(), p.members(g).unwrap())
        }
    }

    Ok(TestResult::passed())
}

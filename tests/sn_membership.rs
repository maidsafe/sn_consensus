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
use sn_membership::{
    Ballot, Error, Generation, Membership, Reconfig, Result, SignedVote, Vote, VoteResponse,
};

static INIT: std::sync::Once = std::sync::Once::new();

fn init() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[test]
fn test_membership_reject_changing_reconfig_when_one_is_in_progress() -> Result<()> {
    init();
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
    init();
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
    init();
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
    init();
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
fn test_membership_returns_catchup_packets_from_previous_gen() -> Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(0, 2, &mut rng);

    let vote = net.proc_mut(1).unwrap().propose(Reconfig::Join(111))?;
    net.enqueue_packets([Packet {
        source: 1,
        dest: 1,
        vote,
    }]);

    let stale_vote = net.proc_mut(2).unwrap().sign_vote(Vote {
        gen: 1,
        ballot: Ballot::Propose(Reconfig::Join(222)),
        faults: Default::default(),
    })?;
    let stale_packets = net.broadcast_packets(2, &stale_vote);

    assert_eq!(stale_packets.len(), 2);

    net.drain_queued_packets()?;

    assert_eq!(
        net.proc(1).unwrap().members(1).unwrap(),
        BTreeSet::from_iter([111])
    );
    assert!(net.proc(2).unwrap().members(1).is_err());

    for packet in stale_packets {
        let resp = net.procs[0].handle_signed_vote(packet.vote);
        assert!(resp.is_ok());
        match resp.unwrap() {
            VoteResponse::Broadcast(signed_vote) => {
                if let Ballot::SuperMajority { proposals, .. } = &signed_vote.vote.ballot {
                    assert_eq!(Vec::from_iter(proposals.keys()), vec![&Reconfig::Join(111)]);
                } else {
                    panic!("Expected SuperMajority Ballot, got: {:?}", signed_vote);
                }

                net.procs[1].handle_signed_vote(signed_vote)?;
            }
            e => panic!("Expected broadcast, got {:?}", e),
        }
    }

    net.generate_msc("test_membership_returns_catchup_packets_from_previous_gen.msc")?;

    assert_eq!(
        net.proc(1).unwrap().members(1).unwrap(),
        BTreeSet::from_iter([111])
    );
    assert_eq!(
        net.proc(2).unwrap().members(1).unwrap(),
        BTreeSet::from_iter([111])
    );

    Ok(())
}

#[test]
fn test_membership_reject_votes_with_invalid_signatures() -> Result<()> {
    init();
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
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs((nprocs * 2) / 3, nprocs, &mut rng);

        for i in 0..net.procs.len() {
            let a_i = net.procs[i].id();
            let vote = net.procs[i].propose(Reconfig::Join(i as u8))?;
            net.broadcast(a_i, vote);
        }

        net.drain_queued_packets()?;

        assert!(net.packets.is_empty());

        net.generate_msc(&format!("split_vote_{}.msc", nprocs))?;

        let expected_members = BTreeSet::from_iter(0..=(2 * nprocs) / 3);
        for i in 0..nprocs {
            println!("proc {i:?}");
            let proc = &net.procs[i as usize];
            assert_eq!(proc.gen, 1);
            assert_eq!(proc.members(1)?, expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_membership_round_robin_split_vote() -> Result<()> {
    init();
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
    init();
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
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, 3, &mut rng);

    let p0 = net.procs[0].id();
    let vote = net.procs[0].propose(Reconfig::Join(0)).unwrap();
    net.broadcast(p0, vote);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("test_membership_simple_proposal.msc")?;

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
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(1, 2, &mut rng);
    let p0 = net.procs[0].id();

    let q = &mut net.procs[0];
    let vote = q.propose(Reconfig::Join(1)).unwrap();
    net.broadcast(p0, vote);

    net.enqueue_anti_entropy(1, 0);
    net.enqueue_anti_entropy(1, 0);

    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    for p in net.procs.iter() {
        assert_eq!(p.members(p.gen)?, net.procs[0].members(p.gen)?);
    }
    Ok(())
}

#[test]
fn test_membership_interpreter_qc2() -> Result<()> {
    init();
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
    let expected_members = net.procs[0].members(net.procs[0].gen)?;
    for p in net.procs.iter() {
        assert_eq!(p.consensus.votes, Default::default());
        assert_eq!(p.consensus.decision, None);
        assert_eq!(p.members(p.gen)?, expected_members);
    }

    Ok(())
}

#[test]
fn test_membership_interpreter_qc3() {
    init();
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

    assert!(net.drain_queued_packets().is_ok());

    net.generate_msc("test_membership_interpreter_qc3.msc")
        .unwrap();
}

#[test]
fn test_membership_interpreter_qc4() -> Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);

    fn super_majority(m: usize, n: usize) -> bool {
        3 * m > 2 * n
    }

    let mut net = Net::with_procs(0, 1, &mut rng);
    {
        let reconfig = Reconfig::Join(0);
        let vote = net.procs[0].propose(reconfig).unwrap();
        net.reconfigs_by_gen.entry(1).or_default().insert(reconfig);
        net.broadcast(1, vote);
    }

    {
        net.deliver_packet_from_source(1).unwrap();
    }

    {
        let anti_entropy_packets = net.procs[0]
            .anti_entropy(0)?
            .into_iter()
            .map(|vote| Packet {
                source: 1,
                dest: 1,
                vote,
            });
        net.enqueue_packets(anti_entropy_packets);
    }

    {
        let reconfig = Reconfig::Join(1);
        let vote = net.procs[0].propose(reconfig).unwrap();
        net.reconfigs_by_gen.entry(2).or_default().insert(reconfig);
        net.broadcast(1, vote);
    }

    assert_eq!(net.procs[0].members(1).unwrap(), BTreeSet::from_iter([0]));
    net.deliver_packet_from_source(1).unwrap();
    assert_eq!(net.procs[0].members(1).unwrap(), BTreeSet::from_iter([0]));

    net.drain_queued_packets().unwrap();

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

    let max_gen = procs_by_gen.keys().last().unwrap();

    // And procs at each generation should have agreement on members
    for (gen, procs) in procs_by_gen.iter() {
        let mut proc_iter = procs.iter();
        let first = proc_iter.next().ok_or(Error::NoMembers)?;
        for proc in proc_iter {
            assert_eq!(
                first.members(first.gen)?,
                proc.members(proc.gen)?,
                "gen: {}",
                gen
            );
        }
    }

    let proc_at_max_gen = procs_by_gen[max_gen].get(0).ok_or(Error::NoMembers)?;
    assert!(super_majority(
        procs_by_gen[max_gen].len(),
        proc_at_max_gen.consensus.n_elders
    ));

    Ok(())
}

#[test]
fn test_membership_procs_refuse_to_propose_competing_votes() -> Result<()> {
    init();
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
    init();
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
        proc.validate_reconfig(Reconfig::Join(7), proc.gen + 1),
        Err(Error::MembersAtCapacity)
    ));

    Ok(())
}

#[test]
fn test_membership_bft_consensus_qc1() -> Result<()> {
    init();
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, 7, &mut rng);
    let faulty = BTreeSet::from_iter([2, 6]);

    // send a randomized packet
    let packet = Packet {
        source: 2,
        dest: 1,
        vote: net.proc(2).unwrap().sign_vote(Vote {
            gen: 1,
            ballot: Ballot::Propose(Reconfig::Join(240)),
            faults: Default::default(),
        })?,
    };
    net.enqueue_packets(vec![packet]);
    let packet = Packet {
        source: 2,
        dest: 1,
        vote: SignedVote {
            voter: 2,
            ..net.proc(6).unwrap().sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(Reconfig::Join(115)),
                faults: Default::default(),
            })?
        },
    };
    net.enqueue_packets(vec![packet]);
    net.drain_queued_packets()?;

    net.generate_msc("test_membership_bft_consensus_qc1.msc")?;

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| !faulty.contains(&p.id())));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        for g in 1..=p.gen {
            assert!(p.consensus_at_gen(g).unwrap().decision.is_some())
        }
        assert_eq!(p.consensus.votes, BTreeMap::default());
        assert_eq!(p.consensus.decision, None);
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
    init();
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

    net.generate_msc("test_membership_bft_consensus_qc2.msc")?;

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| !faulty.contains(&p.id())));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        for g in 1..=p.gen {
            assert!(p.consensus_at_gen(g).unwrap().decision.is_some())
        }
        assert_eq!(p.consensus.votes, BTreeMap::default());
        assert_eq!(p.consensus.decision, None);
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

#[test]
fn test_membership_bft_consensus_qc3() -> Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let n = 4;
    let mut net = Net::with_procs((2 * n) / 3, n, &mut rng);
    let faulty = 1;
    let proposer_a = 2;
    let proposer_b = n;
    {
        let vote = net
            .proc_mut(proposer_a)
            .unwrap()
            .propose(Reconfig::Join(11))
            .unwrap();
        net.broadcast(proposer_a, vote);
    }

    {
        let packet = Packet {
            source: faulty,
            dest: proposer_b,
            vote: net
                .proc(faulty)
                .unwrap()
                .sign_vote(Vote {
                    gen: 1,
                    ballot: Ballot::Propose(Reconfig::Join(22)),
                    faults: Default::default(),
                })
                .unwrap(),
        };
        net.enqueue_packets(vec![dbg!(packet)]);
    }

    {
        let vote = net
            .proc_mut(proposer_b)
            .unwrap()
            .propose(Reconfig::Join(33))
            .unwrap();
        net.broadcast(proposer_b, vote);
    }

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }

    net.generate_msc("test_membership_bft_consensus_qc3.msc")
        .unwrap();
    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| faulty != p.id()));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        for g in 1..=p.gen {
            assert!(p.consensus_at_gen(g).unwrap().decision.is_some())
        }
        assert_eq!(p.consensus.votes, BTreeMap::default());
        assert_eq!(p.consensus.decision, None);
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
fn test_membership_votes_from_faulty_nodes_dont_contribute_to_vote_counts() -> Result<()> {
    init();

    let n = 5;

    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs((2 * n) / 3, n, &mut rng);

    let faulty = 3;
    let honest = 1;

    {
        // node takes honest action
        let proc = net.proc_mut(honest).unwrap();
        let vote = proc.propose(Reconfig::Join(11)).unwrap();
        net.broadcast(honest, dbg!(vote));
    }

    {
        let faulty_proc = net.proc(faulty).unwrap();
        let packet = Packet {
            source: faulty,
            dest: honest,
            vote: faulty_proc
                .sign_vote(Vote {
                    gen: 1,
                    ballot: Ballot::Propose(Reconfig::Join(22)),
                    faults: Default::default(),
                })
                .unwrap(),
        };
        net.enqueue_packets(vec![packet]);
    }

    net.drain_queued_packets()?;

    net.generate_msc("test_membership_bft_consensus_qc4.msc")?;

    let honest_procs = Vec::from_iter(net.procs.iter().filter(|p| faulty != p.id()));

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        println!("Checking {}", p.id());
        for g in 1..=p.gen {
            println!(" at gen {g}");
            assert!(p.consensus_at_gen(g).unwrap().decision.is_some())
        }
        assert_eq!(p.consensus.votes, BTreeMap::default());
        assert_eq!(p.consensus.decision, None);
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

#[quickcheck]
fn prop_interpreter(n: u8, instructions: Vec<Instruction>, seed: u128) -> eyre::Result<TestResult> {
    init();
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    fn super_majority(m: usize, n: usize) -> bool {
        3 * m > 2 * n
    }

    let n = n as usize % 6 + 1;
    if instructions.len() > 5 {
        return Ok(TestResult::discard());
    }

    let mut net = Net::with_procs(((2 * n) / 3) as u8, n as u8, &mut rng);

    for instruction in instructions {
        match instruction {
            Instruction::RequestJoin(p, q_idx) => {
                let reconfig = Reconfig::Join(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_id = q.id();
                match q.propose(reconfig) {
                    Ok(vote) => {
                        net.reconfigs_by_gen
                            .entry(vote.vote.gen)
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
                            .entry(vote.vote.gen)
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

    net.drain_queued_packets()?;
    assert!(net.packets.is_empty());

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
        for proc in proc_iter {
            assert_eq!(
                first.members(first.gen)?,
                proc.members(proc.gen)?,
                "gen: {}",
                gen
            );
        }
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
    init();
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

    let valid_res = proc.validate_reconfig(reconfig, proc.gen + 1);
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
    actions: Vec<u8>,
    faulty: Vec<u8>,
    seed: u128,
) -> Result<()> {
    init();
    let n = n % 6 + 1;
    let recursion_limit = recursion_limit % (n / 2).max(1);
    let faulty = BTreeSet::from_iter(
        faulty
            .into_iter()
            .map(|p| p % n)
            .filter(|p| p != &0) // genesis can not be faulty
            .take((n / 3u8).saturating_sub(1) as usize),
    );

    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

    let mut net = Net::with_procs((2 * n) / 3, n, &mut rng);

    let faulty = BTreeSet::from_iter(faulty.into_iter().map(|idx| net.procs[idx as usize].id()));

    for action in actions.iter().take(7) {
        match action % 3 {
            0 if !faulty.is_empty() => {
                // send a randomized packet
                let packet = net.gen_faulty_packet(recursion_limit, &faulty, &mut rng);
                net.enqueue_packets(vec![packet]);
            }
            1 => {
                // node takes honest action
                let proc = if let Some(proc) = net
                    .procs
                    .iter_mut()
                    .filter(|p| !faulty.contains(&p.id())) // honest nodes
                    .filter(|p| p.consensus.votes.is_empty()) // who haven't voted yet
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
        for g in 1..=p.gen {
            assert!(p.consensus_at_gen(g).unwrap().decision.is_some())
        }
        assert_eq!(p.consensus.votes, BTreeMap::default());
        assert_eq!(p.consensus.decision, None);
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

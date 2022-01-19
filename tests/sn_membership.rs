use blsttc::{PublicKeyShare, SecretKeyShare};
use eyre::eyre;
use net::{Net, Packet};
use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng, SeedableRng,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
};

mod net;

use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;
use sn_membership::{
    Ballot, Error, Generation, Reconfig, Result, SignedVote, State, Vote, VoteMsg,
};

#[test]
fn test_reject_changing_reconfig_when_one_is_in_progress() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc: State<u8> = State::random(&mut rng);
    proc.elders = BTreeSet::from_iter([proc.public_key_share()]);
    proc.propose(Reconfig::Join(rng.gen()))?;
    assert!(matches!(
        proc.propose(Reconfig::Join(rng.gen())),
        Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_vote_from_non_member() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let resp = net.procs[1].propose(Reconfig::Join(rng.gen()))?;
    net.enqueue_packets(resp.into_iter().map(|vote_msg| Packet {
        source: p1,
        vote_msg,
    }));
    net.drain_queued_packets()?;
    Ok(())
}

#[test]
fn test_reject_join_if_actor_is_already_a_member() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State {
        forced_reconfigs: vec![(
            0,
            BTreeSet::from_iter((0..1).map(|_| Reconfig::Join(rng.gen()))),
        )]
        .into_iter()
        .collect(),
        ..State::random(&mut rng)
    };
    proc.elders = BTreeSet::from_iter([proc.public_key_share()]);

    let member = proc
        .members(proc.gen)?
        .into_iter()
        .next()
        .ok_or(Error::NoMembers)?;
    assert!(matches!(
        proc.propose(Reconfig::Join(member)),
        Err(Error::JoinRequestForExistingMember { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_leave_if_actor_is_not_a_member() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State::<u8> {
        forced_reconfigs: vec![(
            0,
            BTreeSet::from_iter((0..1).map(|_| Reconfig::Join(rng.gen()))),
        )]
        .into_iter()
        .collect(),
        ..State::random(&mut rng)
    };
    proc.elders = BTreeSet::from_iter([proc.public_key_share()]);

    let resp = proc.propose(Reconfig::Leave(rng.gen()));
    assert!(matches!(resp, Err(Error::LeaveRequestForNonMember { .. })));
}

#[test]
fn test_handle_vote_rejects_packet_from_previous_gen() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let a_0 = net.procs[0].public_key_share();
    let a_1 = net.procs[1].public_key_share();
    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let packets = net.procs[0]
        .propose(Reconfig::Join(rng.gen()))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_0,
            vote_msg,
        })
        .collect::<Vec<_>>();

    let stale_packets = net.procs[1]
        .propose(Reconfig::Join(rng.gen()))?
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_1,
            vote_msg,
        })
        .collect::<Vec<_>>();

    net.procs[1].pending_gen = 0;
    net.procs[1].votes = Default::default();

    assert_eq!(packets.len(), 2); // two members in the network
    assert_eq!(stale_packets.len(), 2);

    net.enqueue_packets(packets);
    net.drain_queued_packets()?;

    for packet in stale_packets {
        let vote = packet.vote_msg.vote;
        assert!(matches!(
            net.procs[0].handle_signed_vote(vote),
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
fn test_reject_votes_with_invalid_signatures() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc: State<u8> = State::random(&mut rng);
    let ballot = Ballot::Propose(Reconfig::Join(rng.gen()));
    let gen = proc.gen + 1;
    let voter = rng.gen::<SecretKeyShare>().public_key_share();
    let bytes = bincode::serialize(&(&ballot, &gen))?;
    let sig = rng.gen::<SecretKeyShare>().sign(&bytes);
    let vote = Vote { gen, ballot };
    let resp = proc.handle_signed_vote(SignedVote { vote, voter, sig });

    assert!(resp.is_err());
    assert!(matches!(resp, Err(Error::InvalidElderSignature)));

    Ok(())
}

#[test]
fn test_split_vote() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs, &mut rng);

        let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
        for proc in net.procs.iter_mut() {
            proc.elders = elders.clone();
        }

        for i in 0..net.procs.len() {
            let a_i = net.procs[i].public_key_share();
            let packets = net.procs[i]
                .propose(Reconfig::Join(i as u8))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        net.drain_queued_packets()?;
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        assert!(net.packets.is_empty());

        net.generate_msc(&format!("split_vote_{}.msc", nprocs))?;

        for i in 0..nprocs {
            assert_eq!(net.procs[i].gen, net.procs[i].pending_gen);
        }
        let proc0_gen = net.procs[0].gen;
        let expected_members = net.procs[0].members(proc0_gen)?;

        for i in 0..nprocs {
            let proc_i_gen = net.procs[i].gen;
            assert_eq!(proc_i_gen, proc0_gen);
            assert_eq!(net.procs[i].members(proc_i_gen)?, expected_members);
        }
    }

    Ok(())
}

#[test]
fn test_round_robin_split_vote() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        let mut net = Net::with_procs(nprocs, &mut rng);

        let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
        for proc in net.procs.iter_mut() {
            proc.elders = elders.clone();
        }

        for i in 0..net.procs.len() {
            let a_i = net.procs[i].public_key_share();
            let packets = net.procs[i]
                .propose(Reconfig::Join(i as u8))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            net.enqueue_packets(packets);
        }

        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].public_key_share())?;
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
            let gen = net.procs[i].gen;
            assert_eq!(gen, proc_0_gen);
            assert_eq!(net.procs[i].members(gen)?, expected_members);
        }
    }
    Ok(())
}

#[test]
fn test_onboarding_across_many_generations() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let packets = net.procs[0]
        .propose(Reconfig::Join(1))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p0).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    net.deliver_packet_from_source(p1).unwrap();
    assert!(net.packets.is_empty());
    let packets = net.procs[0]
        .propose(Reconfig::Join(2))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(packets);

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
fn test_simple_proposal() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, &mut rng);

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let proc_0 = net.procs[0].public_key_share();
    let proc_3 = net.procs[2].public_key_share();
    let packets = net.procs[0]
        .propose(Reconfig::Join(0))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: proc_0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("simple_join.msc")?;

    let members = net.procs[0].members(1).unwrap();
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
fn test_interpreter_qc1() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let reconfig = Reconfig::Join(1);
    let q = &mut net.procs[0];
    let propose_vote_msgs = q.propose(reconfig).unwrap();
    let propose_packets = propose_vote_msgs.into_iter().map(|vote_msg| Packet {
        source: p0,
        vote_msg,
    });
    net.reconfigs_by_gen
        .entry(q.pending_gen)
        .or_default()
        .insert(reconfig);
    net.enqueue_packets(propose_packets);

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
        assert!(p
            .history
            .iter()
            .all(|(_, v)| v.vote.is_super_majority_ballot()));
    }
    Ok(())
}

#[test]
fn test_interpreter_qc2() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, &mut rng);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    let p2 = net.procs[2].public_key_share();

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(1))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.drain_queued_packets();

    let propose_packets = net.procs[0]
        .propose(Reconfig::Join(2))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.drain_queued_packets().unwrap();

    net.generate_msc("interpreter_qc2.msc").unwrap();

    assert!(net.packets.is_empty());

    // We should have no more pending votes.
    let expected_members = net.procs[0].members(net.procs[0].pending_gen).unwrap();
    for p in net.procs.iter() {
        assert_eq!(p.gen, p.pending_gen);
        assert_eq!(p.votes, Default::default());
        assert_eq!(p.members(p.gen).unwrap(), expected_members);
    }

    Ok(())
}

#[test]
fn test_interpreter_qc3() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, &mut rng);

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    let p0 = net.procs[0].public_key_share();
    // 1 requests to join genesis
    let reconfig = Reconfig::Join(0);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_packets = net.procs[0]
        .propose(reconfig)
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });
    net.enqueue_packets(propose_packets);

    net.drain_queued_packets().unwrap();

    let reconfig = Reconfig::Leave(0);
    net.reconfigs_by_gen
        .entry(net.procs[0].gen + 1)
        .or_default()
        .insert(reconfig);

    let propose_packets = net.procs[0]
        .propose(reconfig)
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });

    net.enqueue_packets(propose_packets);

    let q_actor = net.procs[2].public_key_share();
    let anti_entropy_packets = net.procs[0]
        .anti_entropy(0, q_actor)
        .into_iter()
        .map(|vote_msg| Packet {
            source: p0,
            vote_msg,
        });

    net.enqueue_packets(anti_entropy_packets);
    net.drain_queued_packets().unwrap();

    for i in 0..net.procs.len() {
        for j in 0..net.procs.len() {
            net.enqueue_anti_entropy(i, j);
        }
    }

    let res = net.drain_queued_packets();

    net.generate_msc("test_interpreter_qc3.msc").unwrap();

    assert!(res.is_ok());
}

#[test]
fn test_procs_refuse_to_propose_competing_votes() -> Result<()> {
    let rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State::random(rng);
    let proc_id = proc.public_key_share();
    proc.elders = BTreeSet::from_iter([proc_id]);

    proc.propose(Reconfig::Join(0))?;

    // Proposing a second join reconfig for a different member should fail
    let reconfig = Reconfig::Join(1);
    assert!(matches!(
        proc.propose(reconfig),
        Err(Error::ExistingVoteIncompatibleWithNewVote)
    ));
    assert!(!proc
        .votes
        .get(&proc_id)
        .unwrap()
        .supersedes(&proc.sign_vote(Vote {
            ballot: Ballot::Propose(reconfig),
            gen: proc.gen,
        })?));

    Ok(())
}

#[test]
fn test_validate_reconfig_rejects_when_members_at_capacity() -> Result<()> {
    let rng = StdRng::from_seed([0u8; 32]);
    let mut proc = State::random(rng);

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
fn test_bft_consensus_qc1() -> Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(6, &mut rng);
    let faulty = BTreeSet::from_iter([
        net.procs[1].public_key_share(),
        net.procs[5].public_key_share(),
    ]);

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for p in net.procs.iter_mut() {
        p.elders = elders.clone();
    }

    // send a randomized packet
    let packet = Packet {
        source: net.procs[1].public_key_share(),
        vote_msg: VoteMsg {
            vote: SignedVote {
                voter: net.procs[1].public_key_share(),
                ..net.procs[1].sign_vote(Vote {
                    gen: 1,
                    ballot: Ballot::Propose(Reconfig::Join(240)),
                })?
            },
            dest: net.procs[0].public_key_share(),
        },
    };
    net.enqueue_packets(vec![packet]);
    let packet = Packet {
        source: net.procs[1].public_key_share(),
        vote_msg: VoteMsg {
            vote: SignedVote {
                voter: net.procs[1].public_key_share(),
                ..net.procs[5].sign_vote(Vote {
                    gen: 0,
                    ballot: Ballot::Propose(Reconfig::Join(115)),
                })?
            },
            dest: net.procs[0].public_key_share(),
        },
    };
    net.enqueue_packets(vec![packet]);

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }
    net.generate_msc(&format!("bft_consensus_qc1.msc"))?;

    let honest_procs = Vec::from_iter(
        net.procs
            .iter()
            .filter(|p| !faulty.contains(&p.public_key_share())),
    );

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.gen, p.pending_gen);
        assert_eq!(p.votes, BTreeMap::default());
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

    let mut net = Net::with_procs(n, &mut rng);

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.elders = elders.clone();
    }

    for instruction in instructions {
        match instruction {
            Instruction::RequestJoin(p, q_idx) => {
                let reconfig = Reconfig::Join(p);

                let q = &mut net.procs[q_idx.min(n - 1)];
                let q_actor = q.public_key_share();
                match q.propose(reconfig) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: q_actor,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::JoinRequestForExistingMember { .. }) => {
                        assert!(q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::NotElder { .. }) => {
                        assert!(!q.elders.contains(&q.public_key_share()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote) => {
                        // This proc has already committed to a vote this round

                        // This proc has already committed to a vote
                        assert!(!q.votes.get(&q.public_key_share()).unwrap().supersedes(
                            &q.sign_vote(Vote {
                                ballot: Ballot::Propose(reconfig),
                                gen: q.gen,
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
                let q_actor = q.public_key_share();
                match q.propose(reconfig) {
                    Ok(propose_vote_msgs) => {
                        let propose_packets =
                            propose_vote_msgs.into_iter().map(|vote_msg| Packet {
                                source: q_actor,
                                vote_msg,
                            });
                        net.reconfigs_by_gen
                            .entry(q.pending_gen)
                            .or_default()
                            .insert(reconfig);
                        net.enqueue_packets(propose_packets);
                    }
                    Err(Error::LeaveRequestForNonMember { .. }) => {
                        assert!(!q.members(q.gen)?.contains(&p));
                    }
                    Err(Error::NotElder { .. }) => {
                        assert!(!q.elders.contains(&q.public_key_share()));
                    }
                    Err(Error::ExistingVoteIncompatibleWithNewVote) => {
                        // This proc has already committed to a vote
                        assert!(q.votes.get(&q.public_key_share()).unwrap().supersedes(
                            &q.sign_vote(Vote {
                                ballot: Ballot::Propose(reconfig),
                                gen: q.gen,
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
                let source = net.procs[source_idx.min(n - 1)].public_key_share();
                net.deliver_packet_from_source(source)?;
            }
            Instruction::AntiEntropy(gen, p_idx, q_idx) => {
                let p = &net.procs[p_idx.min(n - 1)];
                let q_actor = net.procs[q_idx.min(n - 1)].public_key_share();
                let p_actor = p.public_key_share();
                let anti_entropy_packets =
                    p.anti_entropy(gen, q_actor)
                        .into_iter()
                        .map(|vote_msg| Packet {
                            source: p_actor,
                            vote_msg,
                        });
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
        assert_eq!(p.votes, Default::default());
    }

    let mut procs_by_gen: BTreeMap<Generation, Vec<State<u8>>> = Default::default();

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
        proc_at_max_gen.elders.len()
    ));

    Ok(TestResult::passed())
}

#[quickcheck]
fn prop_validate_reconfig(
    join_or_leave: bool,
    member: u8,
    initial_members: BTreeSet<u8>,
    num_elders: u8,
    seed: u128,
) -> Result<TestResult> {
    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed_buf);

    if num_elders >= 7 {
        return Ok(TestResult::discard());
    }

    let mut proc = State::random(&mut rng);

    for m in initial_members.iter().copied() {
        proc.force_join(m);
    }

    proc.elders = iter::repeat_with(|| rng.gen::<SecretKeyShare>().public_key_share())
        .take(num_elders as usize)
        .chain(iter::once(proc.public_key_share()))
        .collect();

    let all_elders = {
        let mut elders = proc.elders.clone();
        elders.insert(rng.gen::<SecretKeyShare>().public_key_share());
        elders
    };

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
            .take((n / 3) as usize),
    );
    // All non-faulty nodes eventually decide on a reconfig

    let mut seed_buf = [0u8; 32];
    seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
    let mut rng = rand::rngs::StdRng::from_seed(seed_buf);

    let mut net = Net::with_procs(n as usize, &mut rng);

    let faulty = BTreeSet::from_iter(
        faulty
            .into_iter()
            .map(|idx| net.procs[idx as usize].public_key_share()),
    );

    let elders = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));
    for p in net.procs.iter_mut() {
        p.elders = elders.clone();
    }

    let n_actions = rng.gen::<u8>() % 3;

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
                        let source = net.gen_public_key(&mut rng);
                        net.drop_packet_from_source(source);
                    }
                };
            }
            1 => {
                // node takes honest action
                let pks = BTreeSet::from_iter(net.procs.iter().map(State::public_key_share));

                let proc = if let Some(proc) = net
                    .procs
                    .iter_mut()
                    .filter(|p| !faulty.contains(&p.public_key_share())) // filter out faulty nodes
                    .filter(|p| p.elders.contains(&p.public_key_share())) // filter out non-members
                    .filter(|p| p.gen != p.pending_gen) // filter out nodes who have already voted this round
                    .choose(&mut rng)
                {
                    proc
                } else {
                    // No honest node can take an action
                    continue;
                };

                let source = proc.public_key_share();

                let reconfig = match rng.gen::<bool>() {
                    true => Reconfig::Join(
                        iter::repeat_with(|| rng.gen::<u8>())
                            .filter(|m| !proc.members(proc.gen).unwrap().contains(m))
                            .next()
                            .unwrap(),
                    ),
                    false => Reconfig::Leave(
                        proc.members(proc.gen)
                            .unwrap()
                            .into_iter()
                            .choose(&mut rng)
                            .unwrap(),
                    ),
                };

                let packets = Vec::from_iter(
                    proc.propose(reconfig)
                        .unwrap()
                        .into_iter()
                        .map(|vote_msg| Packet { source, vote_msg }),
                );
                net.enqueue_packets(packets);
            }
            _ => {
                // Network delivers a packet
                let source = net.gen_public_key(&mut rng);
                let _ = net.deliver_packet_from_source(source);
            }
        };
    }

    while let Err(e) = net.drain_queued_packets() {
        println!("Error while draining: {e:?}");
    }

    let honest_procs = Vec::from_iter(
        net.procs
            .iter()
            .filter(|p| !faulty.contains(&p.public_key_share())),
    );

    // BFT TERMINATION PROPERTY: all honest procs have decided ==>
    for p in honest_procs.iter() {
        assert_eq!(p.votes, Default::default());
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
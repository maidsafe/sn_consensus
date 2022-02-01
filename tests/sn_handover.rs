use rand::{prelude::StdRng, Rng, SeedableRng};

mod handover_net;
use handover_net::{DummyProposal, Net};

use blsttc::SecretKeyShare;
use std::collections::BTreeSet;

use sn_membership::{Ballot, Error, Handover, Result, SignedVote, Vote};

#[test]
fn test_handover_reject_voter_changing_proposal_when_one_is_in_progress() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc: Handover<u8> = Handover::random(&mut rng, 0);
    proc.consensus.elders = BTreeSet::from_iter([proc.public_key_share()]);
    proc.propose(0)?;
    assert!(matches!(
        proc.propose(1),
        Err(Error::AttemptedFaultyProposal)
    ));
    Ok(())
}

#[test]
fn test_handover_reject_vote_from_non_member() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key_share();
    let p1 = net.procs[1].public_key_share();
    net.procs[0].consensus.elders = BTreeSet::from_iter([p0]);
    net.procs[1].consensus.elders = BTreeSet::from_iter([p0, p1]);

    let vote = net.procs[1].propose(DummyProposal(rng.gen()))?;
    let resp = net.procs[0].handle_signed_vote(vote);
    assert!(matches!(resp, Err(Error::NotElder { .. })));
    Ok(())
}

#[test]
fn test_handover_handle_vote_rejects_packet_from_bad_gen() {
    // make net with 2 elders
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let elders = BTreeSet::from_iter(net.procs.iter().map(Handover::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.consensus.elders = elders.clone();
    }

    // one elder votes with a different generation
    net.procs[1].gen = 401;
    let vote = net.procs[1].propose(DummyProposal(rng.gen())).unwrap();

    // make sure the other elder rejects that vote
    assert!(matches!(
        net.procs[0].handle_signed_vote(vote),
        Err(Error::VoteWithInvalidUniqueSectionId {
            vote_gen: 401,
            gen: 0,
        })
    ));
}

#[test]
fn test_handover_reject_votes_with_invalid_signatures() -> Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc: Handover<u8> = Handover::random(&mut rng, 0);
    let ballot = Ballot::Propose(rng.gen());
    let gen = proc.gen;
    let voter = rng.gen::<SecretKeyShare>().public_key_share();
    let bytes = bincode::serialize(&(&ballot, &gen))?;
    let sig = rng.gen::<SecretKeyShare>().sign(&bytes);
    let vote = Vote {
        gen,
        ballot,
        faults: Default::default(),
    };
    let resp = proc.handle_signed_vote(SignedVote { vote, voter, sig });

    assert!(resp.is_err());
    assert!(matches!(resp, Err(Error::InvalidElderSignature)));

    Ok(())
}

#[test]
fn test_handover_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {} elders", nprocs);

        // make network of nprocs elders
        let mut net = Net::with_procs(nprocs, &mut rng);
        let elders = BTreeSet::from_iter(net.procs.iter().map(Handover::public_key_share));
        for proc in net.procs.iter_mut() {
            proc.consensus.elders = elders.clone();
        }

        // make each elder propose a different thing
        for i in 0..net.procs.len() {
            let a_i = net.procs[i].public_key_share();
            let vote = net.procs[i].propose(DummyProposal(i as u64))?;
            net.broadcast(a_i, vote);
        }
        net.drain_queued_packets()?;

        // make elders notice split and vote for merge votes
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        // make sure they all reach the same conclusion
        let first_voters_value = net.consensus_value(0);
        for i in 0..nprocs {
            println!(
                "[TEST] checking elder {}'s consensus value: {:?}",
                i,
                net.consensus_value(i)
            );
            assert_eq!(net.consensus_value(i), first_voters_value);
        }
    }

    Ok(())
}

#[test]
fn test_handover_round_robin_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {} elders", nprocs);

        // make network of nprocs elders
        let mut net = Net::with_procs(nprocs, &mut rng);
        let elders = BTreeSet::from_iter(net.procs.iter().map(Handover::public_key_share));
        for proc in net.procs.iter_mut() {
            proc.consensus.elders = elders.clone();
        }

        // make each elder propose a different thing
        for i in 0..net.procs.len() {
            let a_i = net.procs[i].public_key_share();
            let vote = net.procs[i].propose(DummyProposal(i as u64))?;
            net.broadcast(a_i, vote);
        }

        // send all the votes before letting others react
        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].public_key_share())?;
            }
        }

        // make elders notice split and vote for merge
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        // generate msc file
        net.generate_msc(&format!("round_robin_split_vote_{}.msc", nprocs))?;

        // make sure they all reach the same conclusion
        let max_proposed_value = nprocs - 1;
        let expected_consensus_value = Some(DummyProposal(max_proposed_value as u64));
        for i in 0..nprocs {
            println!(
                "[TEST] checking elder {}'s consensus value: {:?}",
                i,
                net.consensus_value(i)
            );
            assert_eq!(net.consensus_value(i), expected_consensus_value);
        }
    }
    Ok(())
}

#[test]
fn test_handover_simple_proposal() {
    // make network of n elders
    let n = 4;
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(n, &mut rng);
    let elders = BTreeSet::from_iter(net.procs.iter().map(Handover::public_key_share));
    for proc in net.procs.iter_mut() {
        proc.consensus.elders = elders.clone();
    }

    // release a proposal
    let p0 = net.procs[0].public_key_share();
    let vote = net.procs[0].propose(DummyProposal(42)).unwrap();
    net.broadcast(p0, vote);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("simple_join.msc").unwrap();

    // make sure they all reach the same conclusion
    let first_voters_value = net.consensus_value(0);
    for i in 0..n {
        println!(
            "[TEST] checking voter {}'s consensus value: {:?}",
            i,
            net.consensus_value(i)
        );
        assert_eq!(net.consensus_value(i), first_voters_value);
    }
}

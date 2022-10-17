use blsttc::{SecretKeySet, SecretKeyShare};
use log::info;
use rand::{prelude::StdRng, Rng, SeedableRng};

mod handover_net;
use handover_net::{Net, Packet};
use sn_consensus::{Ballot, Error, Handover, Result, SignedVote, Vote};

static INIT: std::sync::Once = std::sync::Once::new();

fn init() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[test]
fn test_handover_one_faulty_node_and_many_packet_drops() {
    init();
    // make network of 5 elders with one segregated (his network is really bad)
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(3, 5, &mut rng);
    let segregated_elder = net.procs.pop().unwrap();

    // p0 is a bad node and the network is really bad for the segregated elder so he's not connected yet
    // p0 makes 2 proposals:
    // - 1 for the elders to see
    // - 4 for the segregated elder
    let p0 = net.procs[0].id();
    let vote = net.procs[0].propose(1).unwrap();
    net.broadcast(p0, vote);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    // by the time everyone agreed on smth segregated_elder is back online and receives the bad vote
    for i in 0..4 {
        let decision = net.consensus_value(i);
        info!("[TEST] checking voter {i}'s consensus value: {decision:?}");
        assert_eq!(decision, Some(1));
    }

    let bad_vote = net.procs[0]
        .sign_vote(Vote {
            gen: 0,
            ballot: Ballot::Propose(4),
            faults: Default::default(),
        })
        .unwrap();

    net.enqueue_packets([Packet {
        source: p0,
        dest: segregated_elder.id(),
        vote: bad_vote,
    }]);

    net.procs.push(segregated_elder);

    net.procs[1]
        .anti_entropy()
        .unwrap()
        .into_iter()
        .for_each(|v| net.broadcast(2, v));

    net.drain_queued_packets().unwrap();

    net.generate_msc("handover_one_faulty_node_and_many_packet_drops.msc")
        .unwrap();

    // since everyone agreed already they can't change their votes
    // they have reached consensus
    let first_voters_value = net.consensus_value(0);
    for i in 0..5 {
        let decision = net.consensus_value(i);
        info!("[TEST] checking voter {i}'s consensus value: {decision:?}");
        assert_eq!(decision, first_voters_value);
    }

    assert_eq!(first_voters_value, Some(1));
}

#[test]
fn test_handover_reject_voter_changing_proposal_when_one_is_in_progress() -> Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc: Handover<u8> = Handover::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
        0,
    );

    proc.propose(111)?;

    assert!(matches!(
        proc.propose(222),
        Err(Error::AttemptedFaultyProposal)
    ));
    Ok(())
}

#[test]
fn test_handover_reject_vote_from_non_member() -> Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut p0 = Handover::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
        0,
    );
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut p1 = Handover::<u8>::from(
        (1, elders_sk.secret_key_share(1)),
        elders_sk.public_keys(),
        1,
        0,
    );

    let vote = p1.propose(111)?;
    let resp = p0.handle_signed_vote(vote);
    assert!(matches!(dbg!(resp), Err(Error::InvalidElderSignature)));
    Ok(())
}

#[test]
fn test_handover_handle_vote_rejects_packet_from_bad_gen() {
    init();
    // make net with 2 elders
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(1, 2, &mut rng);

    // one elder votes with a different generation
    net.procs[1].gen = 401;
    let vote = net.procs[1].propose(rng.gen()).unwrap();

    // make sure the other elder rejects that vote
    assert!(matches!(
        net.procs[0].handle_signed_vote(vote),
        Err(Error::BadGeneration {
            requested_gen: 401,
            gen: 0,
        })
    ));
}

#[test]
fn test_handover_reject_votes_with_invalid_signatures() -> Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    let elders_sk = SecretKeySet::random(0, &mut rng);
    let mut proc = Handover::<u8>::from(
        (0, elders_sk.secret_key_share(0)),
        elders_sk.public_keys(),
        1,
        0,
    );
    let ballot = Ballot::Propose(rng.gen());
    let gen = proc.gen;
    let voter = 1;
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
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {nprocs} elders");

        // make network of nprocs elders
        let mut net = Net::with_procs((nprocs * 2 + 2) / 3, nprocs, &mut rng);

        // make each elder propose a different thing
        for i in 0..net.procs.len() {
            let a_i = net.procs[i].id();
            let vote = net.procs[i].propose(i as u8)?;
            net.broadcast(a_i, vote);
        }
        net.drain_queued_packets()?;

        // make sure they all reach the same conclusion
        let first_voters_value = net.consensus_value(0);
        for i in 0..nprocs {
            let decision = net.consensus_value(i);
            println!("[TEST] checking elder {i}'s consensus value: {decision:?}");
            assert_eq!(decision, first_voters_value);
        }
    }

    Ok(())
}

#[test]
fn test_handover_round_robin_split_vote() -> eyre::Result<()> {
    init();
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {nprocs} elder(s)");

        // make network of nprocs elders
        let mut net = Net::with_procs((2 * nprocs) / 3, nprocs, &mut rng);

        // make each elder propose a different thing
        for i in 0..net.procs.len() {
            let a_i = net.procs[i].id();
            let vote = net.procs[i].propose(i as u8)?;
            net.broadcast(a_i, vote);
        }

        // send all the votes before letting others react
        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].id())?;
            }
        }

        // generate msc file
        net.generate_msc(&format!("handover_round_robin_split_vote_{}.msc", nprocs))?;

        // make sure they all reach the same conclusion
        let max_proposed_value = nprocs - 1;
        let expected_consensus_value = Some(max_proposed_value as u8);
        for i in 0..nprocs {
            println!("proc {i}");
            let decision = net.consensus_value(i);
            println!("[TEST] checking elder {i}'s consensus value: {decision:?}");
            assert_eq!(decision, expected_consensus_value);
        }
    }
    Ok(())
}

#[test]
fn test_handover_simple_proposal() {
    // make network of n elders
    let n = 4;
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs((n * 2 + 2) / 3, n, &mut rng);

    // release a proposal
    let p0 = net.procs[0].id();
    let vote = net.procs[0].propose(42).unwrap();
    net.broadcast(p0, vote);
    net.drain_queued_packets().unwrap();
    assert!(net.packets.is_empty());

    net.generate_msc("handover_simple_join.msc").unwrap();

    // make sure they all reach the same conclusion
    let first_voters_value = net.consensus_value(0);
    for i in 0..n {
        let decision = net.consensus_value(i);
        println!("[TEST] checking voter {i}'s consensus value: {decision:?}");
        assert_eq!(decision, first_voters_value);
    }
}

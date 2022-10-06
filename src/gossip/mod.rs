trait GossipService {
    fn broadcast_msg(msg: Serializable) -> Result<()>;
}

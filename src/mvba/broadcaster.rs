use super::{bundle::Bundle, NodeId};
use blsttc::SecretKeyShare;

// Broadcaster holds information required to broadcast the messages.
pub struct Broadcaster {
    bundle_id: u32,
    self_id: NodeId,
    _sec_key_share: SecretKeyShare, // TODO: SecretKeyShare or SecretKey?
    broadcast_bundles: Vec<Bundle>,
    send_bundles: Vec<Bundle>,
}

impl Broadcaster {
    pub fn new(bundle_id: u32, self_id: NodeId, sec_key_share: SecretKeyShare) -> Self {
        Self {
            bundle_id,
            self_id,
            _sec_key_share: sec_key_share,
            broadcast_bundles: Vec::new(),
            send_bundles: Vec::new(),
        }
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn send_to(&mut self, module: &str, message: Vec<u8>, _receiver: NodeId) {
        let bdl = Bundle {
            id: self.bundle_id,
            sender: self.self_id,
            module: module.to_string(),
            message,
        };
        self.send_bundles.push(bdl);
    }

    pub fn broadcast(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id: self.bundle_id,
            sender: self.self_id,
            module: module.to_string(),
            message,
        };
        self.broadcast_bundles.push(bdl);
    }

    pub fn take_bundles(&mut self) -> Vec<Vec<u8>> {
        let mut data = Vec::with_capacity(self.broadcast_bundles.len());
        for bdl in &self.broadcast_bundles {
            data.push(bincode::serialize(bdl).unwrap())
        }
        self.broadcast_bundles.clear();
        data
    }

    #[cfg(test)]
    pub fn has_message(&self, msg: &super::vcbc::message::Message) -> bool {
        for bdl in &self.broadcast_bundles {
            if bdl.message.eq(&bincode::serialize(&msg).unwrap()) {
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.broadcast_bundles.clear();
    }
}

use super::{bundle::Bundle, NodeId};
use blsttc::{PublicKeyShare, SecretKeyShare};

// Broadcaster holds information required to broadcast the messages.
// If a node is an observer node, it should't broadcast messages.
// TODO: How to find out it is an observer node or not?
pub struct Broadcaster {
    bundle_id: u32,
    _sec_key_share: SecretKeyShare,
    broadcast_bundles: Vec<Bundle>,
    send_bundles: Vec<Bundle>,
}

impl Broadcaster {
    pub fn new(id: u32, sec_key_share: &SecretKeyShare) -> Self {
        Self {
            bundle_id: id,
            _sec_key_share: sec_key_share.clone(),
            broadcast_bundles: Vec::new(),
            send_bundles: Vec::new(),
        }
    }

    pub fn self_key(&self) -> PublicKeyShare {
        self._sec_key_share.public_key_share()
    }

    pub fn send_to(&mut self, module: &str, message: Vec<u8>, _receiver: NodeId) {
        let bdl = Bundle {
            id: self.bundle_id,
            module: module.to_string(),
            message,
        };
        self.send_bundles.push(bdl);
    }

    pub fn broadcast(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id: self.bundle_id,
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

    // TODO: remove me
    #[allow(dead_code)]
    #[cfg(test)]
    pub fn has_message(&self, msg: &super::vcbc::message::Message) -> bool {
        for bdl in &self.broadcast_bundles {
            if bdl.message.eq(&bincode::serialize(&msg).unwrap()) {
                return true;
            }
        }
        false
    }

    // TODO: remove me
    #[allow(dead_code)]
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.broadcast_bundles.clear();
    }
}

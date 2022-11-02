use super::{bundle::Bundle, NodeId};
use blsttc::{PublicKeyShare, SecretKeyShare};

// Broadcaster holds information required to broadcast the messages.
// If a node is an observer node, it doesn't broadcast messages.
// For observer node SecretKeyShare and Node ID set to None
pub struct Broadcaster {
    bundle_id: u32,
    secret_key: SecretKeyShare,
    node_id: Option<NodeId>,
    bundles: Vec<Bundle>,
}

impl Broadcaster {
    pub fn new(id: u32, secret_key: &SecretKeyShare, node_id: Option<NodeId>) -> Self {
        Self {
            bundle_id: id,
            secret_key: secret_key.clone(),
            node_id,
            bundles: Vec::new(),
        }
    }

    pub fn self_key(&self) -> PublicKeyShare {
        self.secret_key.public_key_share()
    }

    pub fn self_id(&self) -> Option<NodeId> {
        self.node_id
    }

    pub fn push_message(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id: self.bundle_id,
            module: module.to_string(),
            message,
        };
        self.bundles.push(bdl);
    }

    pub fn take_bundles(&mut self) -> Vec<Vec<u8>> {
        let mut data = Vec::with_capacity(self.bundles.len());
        for bdl in &self.bundles {
            data.push(bincode::serialize(bdl).unwrap())
        }
        self.bundles.clear();
        data
    }

    #[cfg(test)]
    pub fn has_message(&self, msg: &super::vcbc::message::Message) -> bool {
        for bdl in &self.bundles {
            if bdl.message.eq(&bincode::serialize(&msg).unwrap()) {
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.bundles.clear();
    }
}

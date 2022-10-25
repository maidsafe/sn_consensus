use super::bundle::Bundle;
use blsttc::{SecretKeyShare, PublicKeyShare};

pub struct Broadcaster {
    id: u32,
    secret_key: SecretKeyShare,
    bundles: Vec<Bundle>,
}

impl Broadcaster {
    pub fn new(id: u32, secret_key: &SecretKeyShare) -> Self {
        Self {
            id,
            secret_key: secret_key.clone(),
            bundles: Vec::new(),
        }
    }

    pub fn self_key(&self) -> PublicKeyShare {
        self.secret_key.public_key_share()
    }

    pub fn push_message(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id: self.id,
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
    pub fn has_message(&self, data: &Vec<u8>) -> bool {
        for bdl in &self.bundles {
            if bdl.message.eq(data) {
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

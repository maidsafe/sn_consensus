use minicbor::{encode, to_vec};
use super::{crypto::public::{PubKey}, bundle::Bundle};

pub struct Broadcaster {
    id: u32,
    self_key: PubKey,
    bundles: Vec<Bundle>,
}

impl Broadcaster {
    pub fn new(id: u32, self_key: &PubKey) -> Self {
        Self {
            id,
            self_key: self_key.clone(),
            bundles: Vec::new(),
        }
    }

    pub fn self_key(&self) -> &PubKey {
        &self.self_key
    }

    pub fn push_message(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id:self.id,
            module: module.to_string(),
            message,
        };
        self.bundles.push(bdl);
    }

    pub fn take_bundles(&mut self) -> Vec<Vec<u8>> {
        let mut data  = Vec::with_capacity(self.bundles.len());
        for bdl in &self.bundles {
            data.push(to_vec(bdl).unwrap())
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
        return false;
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.bundles.clear();
    }
}

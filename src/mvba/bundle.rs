use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub id: u32,
    pub module: String, // TODO: use enum
    pub message: Vec<u8>,
}

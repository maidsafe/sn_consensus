use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub id: u32,
    pub module: String,
    pub message: Vec<u8>,
}

use blsttc::{Signature, SignatureShare};


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Action {
    PreProcess(bool, SignatureShare),

}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub id: String,
    pub action: Action,
}

impl Message {
    pub fn action_str(&self) -> &str {
        match self.action {
            Action::PreProcess(_,_) => "pre-process",
        }
    }
}

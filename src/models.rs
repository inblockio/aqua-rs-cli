use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize,  Clone)]
pub struct PageDataContainer<HashChain: std::marker::Sync + std::marker::Send> {
    pub pages: Vec<HashChain>,
}
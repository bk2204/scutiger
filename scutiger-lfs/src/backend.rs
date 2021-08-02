use super::processor::{BatchItem, Mode, Oid};
use scutiger_core::errors::Error;

pub mod local;

pub trait Backend {
    fn batch(&mut self, mode: Mode, oids: &[(Oid, u64)]) -> Result<Vec<BatchItem>, Error>;
}

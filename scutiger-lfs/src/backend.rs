use super::processor::{BatchItem, Mode, Oid};
use bytes::Bytes;
use scutiger_core::errors::Error;
use std::any::Any;
use std::collections::BTreeMap;
use std::io;

pub mod local;

pub trait Backend {
    fn batch(&mut self, mode: Mode, oids: &[(Oid, u64)]) -> Result<Vec<BatchItem>, Error>;
    fn start_upload(
        &mut self,
        oid: &Oid,
        rdr: &mut dyn io::Read,
        args: &BTreeMap<Bytes, Bytes>,
    ) -> Result<Box<dyn Any>, Error>;
    fn finish_upload(&mut self, state: Box<dyn Any>) -> Result<(), Error>;
}

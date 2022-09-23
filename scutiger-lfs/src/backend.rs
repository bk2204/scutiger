#![allow(clippy::mutable_key_type)]

use super::processor::{BatchItem, Mode, Oid, Status};
use bytes::{Bytes, BytesMut};
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
    fn verify(&mut self, oid: &Oid, args: &BTreeMap<Bytes, Bytes>) -> Result<Status, Error>;
    fn download(
        &mut self,
        oid: &Oid,
        args: &BTreeMap<Bytes, Bytes>,
    ) -> Result<(Box<dyn io::Read>, Option<u64>), Error>;
    fn lock_backend<'a>(&'a self) -> Box<dyn LockBackend + 'a>;
}

pub trait Lock {
    fn unlock(&self) -> Result<(), Error>;
    fn id(&self) -> String;
    fn path(&self) -> &Bytes;
    fn formatted_timestamp(&self) -> String;
    fn ownername(&self) -> &str;
    fn as_lock_spec(&self, owner_id: bool) -> Result<Vec<Bytes>, Error>;
    fn as_arguments(&self) -> Vec<Bytes> {
        let mut b = BytesMut::new();
        b.extend_from_slice(b"path=");
        b.extend_from_slice(self.path());
        b.extend_from_slice(b"\n");
        vec![
            format!("id={}\n", self.id()).into(),
            b.into(),
            format!("locked-at={}\n", self.formatted_timestamp()).into(),
            format!("ownername={}\n", self.ownername()).into(),
        ]
    }
}

#[allow(clippy::wrong_self_convention)]
pub trait LockBackend {
    fn create(&self, path: &Bytes) -> Result<Box<dyn Lock>, Error>;
    fn unlock(&self, lock: Box<dyn Lock>) -> Result<(), Error> {
        lock.unlock()
    }
    fn from_path(&self, path: &Bytes) -> Result<Option<Box<dyn Lock>>, Error>;
    fn from_id(&self, id: &str) -> Result<Option<Box<dyn Lock>>, Error>;
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = Result<Box<dyn Lock>, Error>> + 'a>;
}

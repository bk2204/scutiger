use super::Backend;
use crate::processor::{BatchItem, Mode, Oid};
use scutiger_core::errors::Error;
use std::path::Path;

pub struct LocalBackend<'a> {
    lfs_path: &'a Path,
    umask: u32,
    timestamp: Option<i64>,
}

impl<'a> LocalBackend<'a> {
    pub fn new(lfs_path: &'a Path, umask: u32, timestamp: Option<i64>) -> Self {
        LocalBackend {
            lfs_path,
            umask,
            timestamp,
        }
    }
}

impl<'a> Backend for LocalBackend<'a> {
    fn batch(&mut self, _mode: Mode, oids: &[(Oid, u64)]) -> Result<Vec<BatchItem>, Error> {
        oids.iter()
            .map(|(oid, batch_size)| {
                let maybe_size = oid.size_at_path(self.lfs_path);
                Ok(BatchItem {
                    oid: oid.clone(),
                    size: maybe_size.unwrap_or(*batch_size),
                    present: maybe_size.is_some(),
                })
            })
            .collect()
    }
}

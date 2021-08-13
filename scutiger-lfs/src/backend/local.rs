use super::Backend;
use crate::processor::{BatchItem, Mode, Oid, Status};
use bytes::Bytes;
use scutiger_core::errors::{Error, ErrorKind};
use std::any::Any;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};

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

    #[cfg(unix)]
    fn fix_permissions(&self, path: &Path) -> Result<Status, Error> {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o777 & !self.umask);
        fs::set_permissions(path, perms)?;
        Ok(Status::success())
    }

    #[cfg(not(unix))]
    fn fix_permissions(&self, path: &Path) -> Result<Status, Error> {
        Ok(Status::success())
    }
}

pub struct UploadState {
    oid: Oid,
    tempfile: Option<NamedTempFile>,
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

    fn start_upload(
        &mut self,
        oid: &Oid,
        rdr: &mut dyn io::Read,
        _args: &BTreeMap<Bytes, Bytes>,
    ) -> Result<Box<dyn Any>, Error> {
        let mut tempdir: PathBuf = self.lfs_path.into();
        tempdir.push("incomplete");
        let mut tempfile = Builder::new()
            .prefix(oid.as_str())
            .rand_bytes(12)
            .tempfile_in(&tempdir)?;
        io::copy(rdr, tempfile.as_file_mut())?;
        Ok(Box::new(UploadState {
            oid: oid.clone(),
            tempfile: Some(tempfile),
        }))
    }

    fn finish_upload(&mut self, mut state: Box<dyn Any>) -> Result<(), Error> {
        let state = match state.downcast_mut::<UploadState>() {
            Some(state) => state,
            None => return Err(Error::new_simple(ErrorKind::DowncastError)),
        };
        // This is a valid file.  Let's create any missing directories and then rename it.  This
        // uses an atomic rename, which should work
        // on all platforms.
        let dest_path = state.oid.expected_path(self.lfs_path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        state
            .tempfile
            .take()
            .unwrap()
            .into_temp_path()
            .persist(&dest_path)
            .map_err(|e| Error::new(ErrorKind::IOError, Some(e)))?;
        self.fix_permissions(&dest_path)?;
        Ok(())
    }
}

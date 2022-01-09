use super::{Backend, Lock, LockBackend};
use crate::processor::{ArgumentParser, BatchItem, Mode, Oid, Status};
use bytes::{Bytes, BytesMut};
use chrono::{TimeZone, Utc};
use scutiger_core::errors::{Error, ErrorKind};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
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

    fn verify(&mut self, oid: &Oid, args: &BTreeMap<Bytes, Bytes>) -> Result<Status, Error> {
        let expected_size: u64 = ArgumentParser::parse_value_as_integer(args, b"size")?;
        let path = oid.expected_path(self.lfs_path);
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Status::new_failure(404, "not found".as_bytes()))
            }
            Err(e) => return Err(e.into()),
        };
        let actual_size = metadata.len();
        if actual_size == expected_size {
            Ok(Status::success())
        } else {
            Ok(Status::new_failure(
                409,
                "mismatched size or cryptographic collision".as_bytes(),
            ))
        }
    }

    fn download(
        &mut self,
        oid: &Oid,
        _args: &BTreeMap<Bytes, Bytes>,
    ) -> Result<(Box<dyn io::Read>, Option<u64>), Error> {
        let path = oid.expected_path(self.lfs_path);
        let file = fs::File::open(path)?;
        let metadata = file.metadata()?;
        Ok((Box::new(file), Some(metadata.len())))
    }

    fn lock_backend<'b>(&'b self) -> Box<dyn LockBackend + 'b> {
        let mut buf = PathBuf::from(self.lfs_path);
        buf.push("locks");
        Box::new(LocalLockBackend {
            backend: self,
            lock_path: buf,
        })
    }
}

struct LockFile {
    path: PathBuf,
    temp: PathBuf,
}

impl LockFile {
    fn new(path: &Path) -> Result<LockFile, Error> {
        let mut temp = path.to_owned();
        temp.set_extension("lock");
        Ok(LockFile {
            path: path.to_owned(),
            temp,
        })
    }

    fn write(&self, data: &[u8]) -> Result<(), Error> {
        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.temp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(Error::new_simple(ErrorKind::Conflict))
            }
            Err(e) => return Err(e.into()),
        };
        f.write_all(data)?;
        f.flush()?;
        drop(f);
        Ok(())
    }

    #[allow(unused_must_use)]
    fn persist(self) -> Result<(), Error> {
        match fs::hard_link(&self.temp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(Error::new_simple(ErrorKind::Conflict))
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for LockFile {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        // We don't care if the file removal failed.  We did the best we could.
        fs::remove_file(&self.temp);
    }
}

struct LocalBackendLock {
    root: PathBuf,
    path_name: Bytes,
    time: i64,
    ownername: String,
}

impl LocalBackendLock {
    const VERSION: &'static str = "v1";

    fn hash_for(path: &Bytes) -> String {
        let mut hash = Sha256::new();
        hash.update(Self::VERSION.as_bytes());
        hash.update(b":");
        hash.update(&path);
        hex::encode(hash.finalize())
    }

    fn parse(data: Vec<u8>) -> Option<(i64, Bytes)> {
        let v: Vec<Vec<u8>> = data.splitn(3, |&x| x == b':').map(|x| x.into()).collect();
        if v.len() != 3 || v[0] != Self::VERSION.as_bytes() {
            return None;
        }
        let s: String = String::from_utf8(v[1].clone()).ok()?;
        let time = s.parse().ok()?;
        Some((time, v[2].clone().into()))
    }

    #[cfg(windows)]
    fn current_user(&self) -> Result<String, Error> {
        Ok("unknown".into())
    }

    #[cfg(unix)]
    fn current_user(&self) -> Result<String, Error> {
        let uid = unsafe { libc::getuid() } as u32;
        match passwd::Passwd::from_uid(uid) {
            Some(pwd) => Ok(pwd.name),
            None => Ok(format!("uid {}", uid)),
        }
    }
}

impl Lock for LocalBackendLock {
    fn unlock(&self) -> Result<(), Error> {
        let id = Self::hash_for(&self.path_name);
        let mut filename = self.root.clone();
        filename.push(id);
        fs::remove_file(&filename)?;
        Ok(())
    }

    fn id(&self) -> String {
        Self::hash_for(&self.path_name)
    }

    fn path(&self) -> &Bytes {
        &self.path_name
    }

    fn formatted_timestamp(&self) -> String {
        Utc.timestamp(self.time, 0).to_rfc3339()
    }

    fn ownername(&self) -> &str {
        &self.ownername
    }

    fn as_lock_spec(&self, owner_id: bool) -> Result<Vec<Bytes>, Error> {
        let id = self.id();
        let mut v = vec![
            format!("lock {}\n", id).as_bytes().into(),
            ([b"path ", id.as_bytes(), b" ", self.path(), b"\n"])
                .join(b"" as &[u8])
                .into(),
            format!("locked-at {} {}\n", id, self.formatted_timestamp())
                .as_bytes()
                .into(),
            format!("ownername {} {}\n", id, self.ownername())
                .as_bytes()
                .into(),
        ];
        if owner_id {
            let user = self.current_user()?;
            let who = if user == self.ownername() {
                "ours"
            } else {
                "theirs"
            };
            v.push(format!("owner {} {}\n", id, who).as_bytes().into());
        }
        Ok(v)
    }
}

struct LocalLockBackend<'a> {
    backend: &'a LocalBackend<'a>,
    lock_path: PathBuf,
}

impl<'a> LocalLockBackend<'a> {
    fn timestamp(&self) -> i64 {
        self.backend.timestamp.unwrap_or_else(|| {
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(e) => -(e.duration().as_secs() as i64),
            }
        })
    }

    #[cfg(windows)]
    fn user_for_file(path: &Path) -> Result<String, Error> {
        Ok("unknown".into())
    }

    #[cfg(unix)]
    fn user_for_file(path: &Path) -> Result<String, Error> {
        use std::os::unix::fs::MetadataExt;
        let st = fs::metadata(path)?;
        match passwd::Passwd::from_uid(st.uid()) {
            Some(pwd) => Ok(pwd.name),
            None => Ok(format!("uid {}", st.uid())),
        }
    }
}

impl<'a> LockBackend for LocalLockBackend<'a> {
    fn create(&self, path: &Bytes) -> Result<Box<dyn Lock>, Error> {
        let id = LocalBackendLock::hash_for(path);
        let mut b: BytesMut = format!("{}:{}:", LocalBackendLock::VERSION, self.timestamp()).into();
        b.extend_from_slice(path);
        let mut filename = self.lock_path.clone();
        filename.push(id);
        let lock = LockFile::new(&filename)?;
        lock.write(&b)?;
        lock.persist()?;
        let user = Self::user_for_file(&filename).unwrap_or_else(|_| "unknown".into());
        Ok(Box::new(LocalBackendLock {
            root: self.lock_path.clone(),
            path_name: path.clone(),
            time: self.timestamp(),
            ownername: user,
        }))
    }

    fn from_path(&self, path: &Bytes) -> Result<Option<Box<dyn Lock>>, Error> {
        let id = LocalBackendLock::hash_for(path);
        match self.from_id(&id) {
            Ok(None) => Ok(None),
            Ok(Some(l)) if l.path() != path => {
                // This should never happen except with corruption, since otherwise we'd need a
                // collision of SHA-256.
                Err(Error::from_message(
                    ErrorKind::CorruptData,
                    "unexpected filename in parsed lock",
                ))
            }
            Ok(Some(l)) => Ok(Some(l)),
            Err(e) => Err(e),
        }
    }

    fn from_id(&self, id: &str) -> Result<Option<Box<dyn Lock>>, Error> {
        let mut filename = self.lock_path.clone();
        filename.push(id);
        let mut f = match fs::OpenOptions::new().read(true).open(&filename) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        let user = Self::user_for_file(&filename).unwrap_or_else(|_| "unknown".into());
        let (time, parsed_path) = match LocalBackendLock::parse(v) {
            Some(x) => x,
            None => {
                return Err(Error::from_message(
                    ErrorKind::CorruptData,
                    "invalid parsed lock",
                ))
            }
        };
        Ok(Some(Box::new(LocalBackendLock {
            root: self.lock_path.clone(),
            path_name: parsed_path,
            time,
            ownername: user,
        })))
    }

    fn iter<'b>(&'b self) -> Box<dyn Iterator<Item = Result<Box<dyn Lock>, Error>> + 'b> {
        Box::new(LockSetIterator::new(self, &self.lock_path))
    }
}

struct LockSetIterator<'a> {
    data: Vec<fs::DirEntry>,
    err: Option<Error>,
    item: usize,
    done: bool,
    backend: &'a LocalLockBackend<'a>,
}

impl<'a> LockSetIterator<'a> {
    fn new(backend: &'a LocalLockBackend, path: &Path) -> LockSetIterator<'a> {
        let data: Result<Vec<fs::DirEntry>, io::Error> = match fs::read_dir(path) {
            Ok(iter) => iter.collect(),
            Err(e) => Err(e),
        };
        let (data, err) = match data {
            Ok(mut v) => {
                v.sort_by_key(fs::DirEntry::file_name);
                (v, None)
            }
            Err(e) => (vec![], Some(e.into())),
        };
        LockSetIterator {
            data,
            err,
            item: 0,
            done: false,
            backend,
        }
    }
}

impl<'a> Iterator for LockSetIterator<'a> {
    type Item = Result<Box<dyn Lock>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.err.take(), self.done) {
            (_, true) => None,
            (Some(e), false) => {
                self.done = true;
                Some(Err(e))
            }
            (None, false) => {
                while self.item < self.data.len() {
                    let pos = self.item;
                    self.item += 1;
                    let item = &self.data[pos];
                    let filename = item.file_name();
                    let filename = filename.to_string_lossy();
                    match self.backend.from_id(&filename) {
                        Ok(Some(l)) => return Some(Ok(l)),
                        _ => continue,
                    };
                }
                None
            }
        }
    }
}

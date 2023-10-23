#![allow(clippy::mutable_key_type)]
#![allow(clippy::match_like_matches_macro)]

use backend::Backend;
use bytes::Bytes;
use digest::Digest;
use scutiger_core::errors::{Error, ErrorKind};
use scutiger_core::pktline;
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub struct Status {
    code: u32,
    args: Option<Vec<Bytes>>,
    messages: Option<Vec<Bytes>>,
    reader: Option<Box<dyn io::Read>>,
}

impl Status {
    pub fn success() -> Status {
        Status {
            code: 200,
            args: None,
            messages: None,
            reader: None,
        }
    }

    pub fn new_success(messages: Vec<Bytes>) -> Status {
        Status {
            code: 200,
            args: None,
            messages: Some(messages),
            reader: None,
        }
    }

    pub fn new_success_with_code(code: u32, args: Vec<Bytes>) -> Status {
        Status {
            code,
            args: Some(args),
            messages: None,
            reader: None,
        }
    }

    pub fn new_success_with_data(code: u32, args: Vec<Bytes>, messages: Vec<Bytes>) -> Status {
        Status {
            code,
            args: Some(args),
            messages: Some(messages),
            reader: None,
        }
    }

    pub fn new_reader(args: Vec<Bytes>, reader: Box<dyn io::Read>) -> Status {
        Status {
            code: 200,
            args: Some(args),
            messages: None,
            reader: Some(reader),
        }
    }

    pub fn new_failure(code: u32, message: &[u8]) -> Status {
        Status {
            code,
            args: None,
            messages: Some(vec![message.into()]),
            reader: None,
        }
    }

    pub fn new_failure_with_args(code: u32, args: Vec<Bytes>, message: &[u8]) -> Status {
        Status {
            code,
            args: Some(args),
            messages: Some(vec![message.into()]),
            reader: None,
        }
    }
}

impl FromIterator<Bytes> for Status {
    fn from_iter<I: IntoIterator<Item = Bytes>>(iter: I) -> Self {
        Self::new_success(iter.into_iter().collect())
    }
}

pub struct PktLineHandler<R: io::Read, W: io::Write> {
    pub rdr: pktline::Reader<R>,
    wrtr: pktline::Writer<W>,
}

impl<R: io::Read, W: io::Write> PktLineHandler<R, W> {
    pub fn new(rdr: R, wrtr: W) -> Self {
        PktLineHandler {
            rdr: pktline::Reader::new(rdr),
            wrtr: pktline::Writer::new(wrtr),
        }
    }

    pub fn read_to_type(&mut self, typ: pktline::PacketType) -> Result<Vec<Bytes>, Error> {
        self.rdr
            .iter()
            .take_while(|pkt| match pkt {
                Ok(pkt) if pkt.packet_type() == typ => false,
                _ => true,
            })
            .map(|pkt| pkt.map(|p| p.data().unwrap_or(b"").into()))
            .collect()
    }

    pub fn read_to_delim(&mut self) -> Result<Vec<Bytes>, Error> {
        self.read_to_type(pktline::PacketType::Delim)
    }

    pub fn read_to_flush(&mut self) -> Result<Vec<Bytes>, Error> {
        self.read_to_type(pktline::PacketType::Flush)
    }

    pub fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.wrtr.write_all(msg)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        let pkt = pktline::Packet::new(pktline::PacketType::Flush, b"");
        self.wrtr.write_packet(&pkt)?;
        Ok(())
    }

    pub fn delim(&mut self) -> Result<(), Error> {
        let pkt = pktline::Packet::new(pktline::PacketType::Delim, b"");
        self.wrtr.write_packet(&pkt)?;
        Ok(())
    }

    pub fn send_error(&mut self, status: u32, msg: &str) -> Result<(), Error> {
        self.send(format!("status {:03}\n", status).as_bytes())?;
        self.delim()?;
        self.send(msg.as_bytes())?;
        self.flush()?;
        Ok(())
    }

    pub fn send_status(&mut self, status: Status) -> Result<(), Error> {
        let mut status = status;
        self.send(format!("status {:03}\n", status.code).as_bytes())?;
        if let Some(ref args) = status.args {
            for arg in args.iter() {
                self.send(arg)?;
            }
        }
        if let Some(ref messages) = status.messages {
            self.delim()?;
            for msg in messages.iter() {
                self.send(msg)?;
            }
        } else if let Some(ref mut reader) = status.reader {
            self.delim()?;
            io::copy(reader, &mut self.wrtr)?;
        }
        self.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum Mode {
    Upload,
    Download,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Oid {
    // We hold this value as a string because bytes cannot be converted into paths on Windows.
    oid: String,
}

impl Oid {
    pub fn new(oid: &[u8]) -> Result<Self, Error> {
        if Self::valid(oid) {
            // Note that because we've validated that this string contains only lowercase hex
            // characters, this will always be a complete, non-lossy transformation.
            Ok(Oid {
                oid: String::from_utf8_lossy(oid).into(),
            })
        } else {
            Err(Error::new_simple(ErrorKind::InvalidLFSOid))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.oid
    }

    pub fn value(&self) -> &[u8] {
        self.oid.as_bytes()
    }

    pub fn valid(b: &[u8]) -> bool {
        b.len() == 64
            && b.iter()
                .all(|&x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    }

    /// Returns the expected path for this object given the `path` argument, which should be a
    /// `.git/lfs` directory.
    pub fn expected_path(&self, path: &Path) -> PathBuf {
        let mut buf = path.to_path_buf();
        buf.push("objects");
        buf.push(&self.oid[0..2]);
        buf.push(&self.oid[2..4]);
        buf.push(&self.oid);
        buf
    }

    /// Returns a boolean indicating whether an object with this ID is present under the given
    /// path, which should be a `.git/lfs` directory.
    pub fn exists_at_path(&self, path: &Path) -> bool {
        self.expected_path(path).is_file()
    }

    /// Returns `Some(size)`, where `size` is the size of the file if the object with this ID
    /// exists a the given path, which should be a `.git/lfs` directory, or `None` otherwise.
    pub fn size_at_path(&self, path: &Path) -> Option<u64> {
        self.expected_path(path).metadata().ok().map(|x| x.len())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.oid)
    }
}

pub struct BatchItem {
    pub oid: Oid,
    pub size: u64,
    pub present: bool,
}

pub struct ArgumentParser {}

impl ArgumentParser {
    pub fn parse(args: &[Bytes]) -> Result<BTreeMap<Bytes, Bytes>, Error> {
        let mut map = BTreeMap::new();
        for item in args {
            let equals = match item.iter().position(|&x| x == b'=') {
                Some(x) => x,
                None => {
                    return Err(Error::from_message(
                        ErrorKind::ParseError,
                        "unexpected value parsing argument (missing equals)",
                    ));
                }
            };
            if item[item.len() - 1] != b'\n' {
                return Err(Error::from_message(
                    ErrorKind::ParseError,
                    "unexpected value parsing argument (missing newline)",
                ));
            }
            if map
                .insert(
                    item[0..equals].into(),
                    item[equals + 1..item.len() - 1].into(),
                )
                .is_some()
            {
                return Err(Error::from_message(
                    ErrorKind::ExtraData,
                    "unexpected duplicate key",
                ));
            };
        }
        Ok(map)
    }

    pub fn parse_value_as_integer<F: FromStr>(
        args: &BTreeMap<Bytes, Bytes>,
        key: &[u8],
    ) -> Result<F, Error> {
        match args.get(key) {
            Some(x) => Self::parse_integer(x),
            None => Err(Error::from_message(
                ErrorKind::MissingData,
                "missing required header",
            )),
        }
    }

    pub fn parse_integer<F: FromStr>(item: &Bytes) -> Result<F, Error> {
        // This works because if the thing is not valid UTF-8, we'll get a replacement character,
        // which is not a valid digit, and so our parsing will fail.
        match String::from_utf8_lossy(item).parse() {
            Ok(x) => Ok(x),
            Err(_) => Err(Error::from_message(
                ErrorKind::InvalidInteger,
                format!("unexpected value parsing integer: {:?}", item),
            )),
        }
    }
}

pub struct HashingReader<'a, R: io::Read, H: digest::Digest + io::Write> {
    rdr: &'a mut R,
    hash: H,
    size: u64,
}

impl<'a, R: io::Read, H: digest::Digest + io::Write> HashingReader<'a, R, H> {
    pub fn new(rdr: &'a mut R, hash: H) -> Self {
        HashingReader { rdr, hash, size: 0 }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn oid(self) -> Result<Oid, Error> {
        let hex = hex::encode(self.hash.finalize());
        Oid::new(hex.as_bytes())
    }
}

impl<'a, R: io::Read, H: digest::Digest + io::Write> io::Read for HashingReader<'a, R, H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.rdr.read(buf)?;
        self.hash.write_all(&buf[0..count])?;
        self.size += count as u64;
        Ok(count)
    }
}

pub struct Processor<'a, R: io::Read, W: io::Write> {
    handler: PktLineHandler<R, W>,
    backend: Box<dyn Backend + 'a>,
}

impl<'a, R: io::Read, W: io::Write> Processor<'a, R, W> {
    pub fn new(handler: PktLineHandler<R, W>, backend: Box<dyn Backend + 'a>) -> Self {
        Processor { handler, backend }
    }

    fn version(&mut self) -> Result<Status, Error> {
        self.handler.read_to_flush()?;
        Ok(Status::new_success(vec![]))
    }

    fn error(&self, code: u32, msg: &str) -> Result<Status, Error> {
        Ok(Status::new_failure(code, msg.as_bytes()))
    }

    fn read_batch(&mut self, mode: Mode) -> Result<Vec<BatchItem>, Error> {
        let args = ArgumentParser::parse(&self.handler.read_to_delim()?)?;
        let data = match self.handler.read_to_flush() {
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        let hash_algo = args.get(b"hash-algo" as &[u8]);
        match hash_algo.map(|x| x as &[u8]) {
            Some(b"sha256") => (),
            Some(x) => {
                return Err(Error::from_message(
                    ErrorKind::NotAllowed,
                    format!(
                        "{} is not a permitted hash algorithm",
                        String::from_utf8_lossy(x)
                    ),
                ))
            }
            None => (),
        }
        let oids = data
            .iter()
            .map(|line| {
                if line.is_empty() || line[line.len() - 1] != b'\n' {
                    return Err(Error::new_simple(ErrorKind::InvalidPacket));
                }
                let pair: Vec<Bytes> = line[0..line.len()]
                    .split(|&b| b == b' ')
                    .map(|x| x.into())
                    .collect();
                if pair.len() != 2 || pair[1].is_empty() {
                    return Err(Error::new_simple(ErrorKind::ParseError));
                }
                let size = &pair[1];
                let size = match String::from_utf8_lossy(&size[0..size.len() - 1]).parse() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::from_message(
                            ErrorKind::InvalidInteger,
                            format!("got {:?}", pair[1]),
                        ))
                    }
                };
                Ok((Oid::new(&pair[0])?, size))
            })
            .collect::<Result<Vec<_>, Error>>();
        self.backend.batch(mode, &oids?)
    }

    fn batch_data(
        &mut self,
        mode: Mode,
        present_action: &str,
        missing_action: &str,
    ) -> Result<Status, Error> {
        let batch = self.read_batch(mode)?;
        Ok(batch
            .iter()
            .map(|item| {
                let size = format!("{}", item.size);
                let action = if item.present {
                    present_action
                } else {
                    missing_action
                };
                [
                    item.oid.value(),
                    b" ",
                    size.as_bytes(),
                    b" ",
                    action.as_bytes(),
                    b"\n",
                ]
                .join(b"" as &[u8])
                .into()
            })
            .collect())
    }

    fn upload_batch(&mut self) -> Result<Status, Error> {
        self.batch_data(Mode::Upload, "noop", "upload")
    }

    fn download_batch(&mut self) -> Result<Status, Error> {
        self.batch_data(Mode::Download, "download", "noop")
    }

    fn size_from_arguments(args: &BTreeMap<Bytes, Bytes>) -> Result<u64, Error> {
        let size = match args.get(b"size" as &[u8]) {
            Some(x) => x,
            None => {
                return Err(Error::from_message(
                    ErrorKind::MissingData,
                    "missing required size header",
                ))
            }
        };
        ArgumentParser::parse_integer(size)
    }

    fn put_object(&mut self, oid: &[u8]) -> Result<Status, Error> {
        let oid = Oid::new(oid)?;
        let args = ArgumentParser::parse(&self.handler.read_to_delim()?)?;
        let expected_size = Self::size_from_arguments(&args)?;
        let mut rdr = HashingReader::new(&mut self.handler.rdr, Sha256::new());
        let state = self.backend.start_upload(&oid, &mut rdr, &args)?;
        let actual_size = rdr.size();
        match actual_size.cmp(&expected_size) {
            Ordering::Less => {
                return Err(Error::from_message(
                    ErrorKind::MissingData,
                    format!("expected {} bytes, got {}", expected_size, actual_size),
                ))
            }
            Ordering::Greater => {
                return Err(Error::from_message(
                    ErrorKind::ExtraData,
                    format!("expected {} bytes, got {}", expected_size, actual_size),
                ))
            }
            Ordering::Equal => (),
        }

        // We're now confident we have the right number of bytes.  Let's check that the OIDs match.
        // This does not need to be constant time because the user has provided both sides of the
        // data and there's no secret values to compare.
        let actual_oid = rdr.oid()?;
        if actual_oid != oid {
            return Err(Error::from_message(
                ErrorKind::CorruptData,
                format!("expected oid {}, got {}", oid, actual_oid),
            ));
        }
        self.backend.finish_upload(state)?;
        Ok(Status::success())
    }

    fn verify_object(&mut self, oid: &[u8]) -> Result<Status, Error> {
        let args = ArgumentParser::parse(&self.handler.read_to_flush()?)?;
        let oid = Oid::new(oid)?;
        self.backend.verify(&oid, &args)
    }

    fn get_object(&mut self, oid: &[u8]) -> Result<Status, Error> {
        let args = ArgumentParser::parse(&self.handler.read_to_flush()?)?;
        let oid = Oid::new(oid)?;
        let (rdr, size) = match self.backend.download(&oid, &args) {
            Ok(x) => x,
            Err(e) if e.io_kind() == io::ErrorKind::NotFound => {
                return Ok(Status::new_failure(404, "not found".as_bytes()))
            }
            Err(e) => return Err(e),
        };
        let args = match size {
            Some(size) => vec![format!("size={}\n", size).into()],
            None => vec![],
        };
        Ok(Status::new_reader(args, rdr))
    }

    fn lock(&mut self) -> Result<Status, Error> {
        let data = match self.handler.read_to_flush() {
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        let args = ArgumentParser::parse(&data)?;
        let path = args.get(b"path" as &[u8]);
        let refname = args.get(b"refname" as &[u8]);
        let path = match (path, refname) {
            (Some(path), Some(_)) => path,
            (_, _) => {
                return Err(Error::from_message(
                    ErrorKind::MissingData,
                    "both path and refname required",
                ))
            }
        };
        let lock_backend = self.backend.lock_backend();
        let mut retried = false;
        while !retried {
            let (ok, lock) = match lock_backend.create(path) {
                Ok(l) => (true, l),
                Err(e) if e.kind() == ErrorKind::Conflict => match lock_backend.from_path(path) {
                    Ok(Some(l)) => (false, l),
                    Ok(None) => {
                        retried = true;
                        continue;
                    }
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };
            return if ok {
                Ok(Status::new_success_with_code(201, lock.as_arguments()))
            } else {
                Ok(Status::new_failure_with_args(
                    409,
                    lock.as_arguments(),
                    b"conflict",
                ))
            };
        }
        unreachable!()
    }

    fn list_locks_for_path(
        &mut self,
        path: &Bytes,
        cursor: Option<&Bytes>,
        use_owner_id: bool,
    ) -> Result<Status, Error> {
        match (self.backend.lock_backend().from_path(path), cursor) {
            (Err(e), _) => Err(e),
            (Ok(None), _) => self.error(404, "not found"),
            (Ok(Some(l)), Some(id)) if l.id().as_bytes() < id => self.error(404, "not found"),
            (Ok(Some(l)), _) => l.as_lock_spec(use_owner_id).map(Status::new_success),
        }
    }

    fn list_locks(&mut self, use_owner_id: bool) -> Result<Status, Error> {
        let args = match self.handler.read_to_flush() {
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        let args = ArgumentParser::parse(&args)?;
        let mut limit = args
            .get(b"limit" as &[u8])
            .map(ArgumentParser::parse_integer)
            .unwrap_or(Ok(100))?;
        if limit == 0 {
            return Err(Error::from_message(
                ErrorKind::NotAllowed,
                "bizarre request for no data",
            ));
        } else if limit > 100 {
            // Let's prevent the user from trying to DoS us.
            limit = 100
        }
        let cursor = args.get(b"cursor" as &[u8]);
        if let Some(path) = args.get(b"path" as &[u8]) {
            return self.list_locks_for_path(path, cursor, use_owner_id);
        };
        let r: Result<Vec<_>, _> = self
            .backend
            .lock_backend()
            .iter()
            .skip_while(|item| match (item, cursor) {
                (Err(_), _) => false,
                (Ok(l), Some(cursor)) => l.id().as_bytes() < cursor,
                (Ok(_), None) => false,
            })
            .take(limit + 1)
            .collect();
        let items = r?;
        let lock_specs: Result<Vec<_>, _> =
            items.iter().map(|l| l.as_lock_spec(use_owner_id)).collect();
        let lock_specs = lock_specs?.iter().flatten().cloned().collect();
        let next_cursor: Vec<Bytes> = if items.len() == limit + 1 {
            vec![format!("next-cursor={}\n", items[limit].id()).into()]
        } else {
            vec![]
        };
        Ok(Status::new_success_with_data(200, next_cursor, lock_specs))
    }

    fn unlock(&mut self, id: &[u8]) -> Result<Status, Error> {
        self.handler.read_to_flush()?;
        let s = match std::str::from_utf8(id) {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::from_message(
                    ErrorKind::CorruptData,
                    "invalid or corrupt ID",
                ))
            }
        };
        let lock_backend = self.backend.lock_backend();
        match lock_backend.from_id(s) {
            Ok(Some(l)) => {
                let args = l.as_arguments();
                match lock_backend.unlock(l) {
                    Ok(()) => Ok(Status::new_success_with_code(200, args)),
                    Err(e) if e.io_kind() == io::ErrorKind::NotFound => {
                        self.error(404, "not found")
                    }
                    Err(e) if e.io_kind() == io::ErrorKind::PermissionDenied => {
                        self.error(403, "forbidden")
                    }
                    Err(e) => Err(e),
                }
            }
            Ok(None) => self.error(404, "not found"),
            Err(e) => Err(e),
        }
    }

    pub fn process_commands(&mut self, mode: Mode) -> Result<(), Error> {
        loop {
            let pkt = match self.handler.rdr.read_packet() {
                Ok(p) => p,
                Err(e) if e.io_kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            let msgs: Vec<_> = match pkt.data() {
                Some(b"") => {
                    self.handler.send_error(400, "no command provided")?;
                    continue;
                }
                Some(bs) => {
                    let bs = if bs[bs.len() - 1] == b'\n' {
                        &bs[0..bs.len() - 1]
                    } else {
                        bs
                    };
                    bs.split(|&b| b == b' ').collect()
                }
                None => {
                    self.handler.send_error(400, "unknown command")?;
                    continue;
                }
            };
            let resp = match (msgs[0], msgs.get(1), mode) {
                (b"version", Some(&b"1"), _) => self.version(),
                (b"version", _, _) => self.error(400, "unknown version"),
                (b"batch", None, Mode::Upload) => self.upload_batch(),
                (b"batch", None, Mode::Download) => self.download_batch(),
                (b"put-object", Some(oid), Mode::Upload) => self.put_object(oid),
                (b"put-object", Some(_), _) => self.error(403, "not allowed"),
                (b"verify-object", Some(oid), Mode::Upload) => self.verify_object(oid),
                (b"verify-object", Some(_), _) => self.error(403, "not allowed"),
                (b"get-object", Some(oid), Mode::Download) => self.get_object(oid),
                (b"get-object", Some(_), _) => self.error(403, "not allowed"),
                (b"lock", None, Mode::Upload) => self.lock(),
                (b"list-lock", None, Mode::Download) => self.list_locks(false),
                (b"list-lock", None, Mode::Upload) => self.list_locks(true),
                (b"unlock", Some(id), Mode::Upload) => self.unlock(id),
                (b"quit", None, _) => {
                    self.handler.send_status(Status::success())?;
                    return Ok(());
                }
                (_, _, _) => self.error(400, "unknown command"),
            };
            match resp {
                Ok(st) => self.handler.send_status(st),
                Err(e) => match e.kind() {
                    ErrorKind::BadPktlineHeader
                    | ErrorKind::InvalidPacket
                    | ErrorKind::UnexpectedPacket
                    | ErrorKind::InvalidLFSOid
                    | ErrorKind::InvalidInteger
                    | ErrorKind::MissingData
                    | ErrorKind::ExtraData
                    | ErrorKind::CorruptData
                    | ErrorKind::NotAllowed
                    | ErrorKind::UnknownCommand => self
                        .handler
                        .send_status(Status::new_failure(400, format!("error: {}", e).as_bytes())),
                    _ => self.handler.send_status(Status::new_failure(
                        500,
                        format!("internal error: {}", e).as_bytes(),
                    )),
                },
            }?;
        }
    }
}

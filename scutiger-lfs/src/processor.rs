#![allow(clippy::match_like_matches_macro)]

use bytes::Bytes;
use scutiger_core::errors::{Error, ErrorKind};
use scutiger_core::pktline;
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
                .all(|&x| (b'0'..=b'9').contains(&x) || (b'a'..=b'f').contains(&x))
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

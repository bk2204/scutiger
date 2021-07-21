#![allow(clippy::match_like_matches_macro)]

use bytes::Bytes;
use scutiger_core::errors::Error;
use scutiger_core::pktline;
use std::io;
use std::io::Write;
use std::iter::FromIterator;

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

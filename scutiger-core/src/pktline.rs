#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

use super::errors::{Error, ErrorKind};
use std::cmp;
use std::io;

/// The type of a packet received.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum PacketType {
    /// A flush packet (0000).
    Flush,
    /// A delimiter packet (0001).
    Delim,
    /// A data packet.
    ///
    /// The contained value is the number of bytes of data read, not the packet value.
    Data(usize),
}

/// A packet of data.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Packet {
    typ: PacketType,
    data: Vec<u8>,
}

impl Packet {
    pub fn new(t: PacketType, data: &[u8]) -> Self {
        Packet {
            typ: t,
            data: data.to_vec(),
        }
    }

    fn new_from_vec(t: PacketType, vec: Vec<u8>) -> Self {
        Packet { typ: t, data: vec }
    }

    pub fn packet_type(&self) -> PacketType {
        self.typ
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self.typ {
            PacketType::Data(_) => Some(&self.data),
            _ => None,
        }
    }
}

pub struct Reader<R: io::Read> {
    rdr: R,
    buf: [u8; 65536],
    len: usize,
}

impl<R: io::Read> Reader<R> {
    const MAX_PACKET_LEN: usize = 65516;

    pub fn new(rdr: R) -> Self {
        Reader {
            rdr,
            buf: [0u8; 65536],
            len: 0,
        }
    }

    fn read_one(rdr: &mut R, buf: &mut [u8]) -> Result<PacketType, Error> {
        let mut hdr = [0u8; 4];
        rdr.read_exact(&mut hdr)?;
        let size = Self::parse_header(hdr)? as usize;
        match size {
            0 => Ok(PacketType::Flush),
            1 => Ok(PacketType::Delim),
            2 | 3 => Err(Error::new_simple(ErrorKind::BadPktlineHeader)),
            n if n > Self::MAX_PACKET_LEN + 4 => {
                Err(Error::new_simple(ErrorKind::BadPktlineHeader))
            }
            _ => {
                rdr.read_exact(&mut buf[0..(size - 4)])?;
                Ok(PacketType::Data(size - 4))
            }
        }
    }

    pub fn read_packet(&mut self) -> Result<Packet, Error> {
        let mut hdr = [0u8; 4];
        self.rdr.read_exact(&mut hdr)?;
        let size = Self::parse_header(hdr)? as usize;
        match size {
            0 => Ok(Packet::new(PacketType::Flush, b"")),
            1 => Ok(Packet::new(PacketType::Delim, b"")),
            2 | 3 => Err(Error::new_simple(ErrorKind::BadPktlineHeader)),
            _ => {
                let mut v = vec![0u8; size - 4];
                self.rdr.read_exact(&mut v)?;
                Ok(Packet::new_from_vec(PacketType::Data(size - 4), v))
            }
        }
    }

    fn parse_header(buf: [u8; 4]) -> Result<u16, Error> {
        let x: Result<Vec<u16>, Error> = buf
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let v = match *x {
                    b'0'...b':' => x - b'0',
                    b'a'...b'g' => x - b'a' + 10,
                    _ => return Err(Error::new_simple(ErrorKind::BadPktlineHeader)),
                };
                Ok((v as u16) << ((3 - i) * 4))
            })
            .collect();
        Ok(x?.into_iter().sum())
    }

    pub fn iter(&mut self) -> iter::ReaderIterator<'_, R> {
        iter::ReaderIterator::new(self)
    }
}

impl<R: io::Read> io::Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let n = cmp::min(self.len, buf.len());
        if n > 0 {
            buf.copy_from_slice(&self.buf[0..n]);
            self.len -= n;
            return Ok(n);
        }
        loop {
            let (r, copy) = if buf.len() >= Self::MAX_PACKET_LEN {
                (Self::read_one(&mut self.rdr, buf), false)
            } else {
                (Self::read_one(&mut self.rdr, &mut self.buf), true)
            };
            let n = match (r, copy) {
                (Ok(PacketType::Delim), _) => return Ok(0),
                (Ok(PacketType::Flush), _) => return Ok(0),
                (Ok(PacketType::Data(0)), false) => n,
                (Ok(PacketType::Data(n)), false) => return Ok(n),
                (Ok(PacketType::Data(n)), true) => n,
                (Err(e), _) => return Err(e.into()),
            };
            if n > 0 {
                let n = cmp::min(n, buf.len());
                buf[0..n].copy_from_slice(&self.buf[0..n]);
                return Ok(n);
            }
        }
    }
}

pub struct Writer<W: io::Write> {
    writer: W,
}

impl<W: io::Write> Writer<W> {
    const MAX_PACKET_LEN: usize = 65516;

    pub fn new(writer: W) -> Self {
        Writer { writer }
    }

    fn write_one(writer: &mut W, buf: &[u8]) -> Result<usize, Error> {
        let header = format!("{:04x}", buf.len() + 4);
        writer.write_all(header.as_bytes())?;
        writer.write_all(&buf)?;
        Ok(buf.len())
    }

    pub fn write_packet(&mut self, pkt: &Packet) -> Result<usize, Error> {
        match pkt.packet_type() {
            PacketType::Flush => {
                self.writer.write_all(b"0000")?;
                self.writer.flush()?;
                Ok(4)
            }
            PacketType::Delim => {
                self.writer.write_all(b"0001")?;
                Ok(4)
            }
            PacketType::Data(_) => Self::write_one(
                &mut self.writer,
                pkt.data()
                    .ok_or_else(|| Error::new_simple(ErrorKind::InvalidPacket))?,
            ),
        }
    }
}

impl<W: io::Write> io::Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let mut total = 0;
        for chunk in buf.chunks(Self::MAX_PACKET_LEN) {
            total += match Self::write_one(&mut self.writer, &chunk) {
                Ok(sz) => sz,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.flush()
    }
}

mod iter {
    use super::{Packet, Reader};
    use crate::errors::Error;
    use std::io;
    use std::iter;

    pub struct ReaderIterator<'a, R: io::Read> {
        rdr: &'a mut Reader<R>,
    }

    impl<'a, R: io::Read> ReaderIterator<'a, R> {
        pub fn new(rdr: &'a mut Reader<R>) -> Self {
            ReaderIterator { rdr }
        }
    }

    impl<'a, R: io::Read> iter::Iterator for ReaderIterator<'a, R> {
        type Item = Result<Packet, Error>;

        fn next(&mut self) -> Option<Result<Packet, Error>> {
            match self.rdr.read_packet() {
                Ok(x) => Some(Ok(x)),
                Err(ref e) if e.io_kind() == io::ErrorKind::UnexpectedEof => None,
                Err(e) => Some(Err(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use super::{PacketType, Reader, Writer};
    use std::io;
    use std::io::Write;

    fn reader_from_buf<'a>(buf: &'a [u8]) -> Reader<io::Cursor<&'a [u8]>> {
        Reader::new(io::Cursor::new(buf))
    }

    fn writer() -> Writer<io::Cursor<Vec<u8>>> {
        Writer::new(io::Cursor::new(Vec::new()))
    }

    fn check_packet(buf: &[u8], r: Result<(PacketType, Option<&[u8]>), Error>) {
        let mut rdr = reader_from_buf(buf);
        let mut v = vec![0u8; 65536];
        let pt = Reader::read_one(&mut rdr.rdr, &mut v);
        let data: Result<(PacketType, Option<&[u8]>), Error> = match pt {
            Ok(PacketType::Data(x)) => {
                v.truncate(x);
                Ok((PacketType::Data(x), Some(&v)))
            }
            Ok(x) => Ok((x, None)),
            Err(e) => Err(e),
        };
        assert_eq!(data, r);

        let mut rdr = reader_from_buf(buf);
        let pkt = rdr.read_packet();
        let unwrapped = match &pkt {
            &Ok(ref p) => Some(p.clone()),
            &Err(_) => None,
        };
        assert_eq!(
            pkt.map(|p| (p.packet_type().clone(), p.data().map(|x| x.to_vec()))),
            r.map(|(pt, sl)| (pt.clone(), sl.map(|x| x.to_vec())))
        );

        if let Some(pkt) = unwrapped {
            let mut wrtr = writer();
            wrtr.write_packet(&pkt).unwrap();
            assert_eq!(wrtr.writer.into_inner(), buf);
        }
    }

    #[test]
    fn pktline_headers() {
        assert_eq!(Reader::<io::Cursor<&[u8]>>::parse_header(*b"0000"), Ok(0));
        assert_eq!(Reader::<io::Cursor<&[u8]>>::parse_header(*b"0001"), Ok(1));
        assert_eq!(Reader::<io::Cursor<&[u8]>>::parse_header(*b"0004"), Ok(4));
        assert_eq!(
            Reader::<io::Cursor<&[u8]>>::parse_header(*b"ffff"),
            Ok(65535)
        );
        assert_eq!(
            Reader::<io::Cursor<&[u8]>>::parse_header(*b"2204"),
            Ok(8708)
        );
        assert_eq!(
            Reader::<io::Cursor<&[u8]>>::parse_header(*b"cafe"),
            Ok(51966)
        );
        assert_eq!(
            Reader::<io::Cursor<&[u8]>>::parse_header(*b"cafE"),
            Err(Error::new_simple(ErrorKind::BadPktlineHeader))
        );
        assert_eq!(
            Reader::<io::Cursor<&[u8]>>::parse_header(*b"\xc2\xa9fe"),
            Err(Error::new_simple(ErrorKind::BadPktlineHeader))
        );
    }

    #[test]
    fn parse_packet() {
        check_packet(b"0000", Ok((PacketType::Flush, None)));
        check_packet(b"0001", Ok((PacketType::Delim, None)));
        check_packet(b"0004", Ok((PacketType::Data(0), Some(b""))));
        check_packet(b"0005a", Ok((PacketType::Data(1), Some(b"a"))));
        check_packet(
            b"0046\xff\xfee3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Ok((
                PacketType::Data(66),
                Some(b"\xff\xfee3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            )),
        );
    }

    #[test]
    fn write_data() {
        let mut wrtr = writer();
        wrtr.write(b"abc").unwrap();
        wrtr.write(b"\xff\xfe\xc2\xa90123456").unwrap();
        assert_eq!(
            wrtr.writer.into_inner(),
            b"0007abc000f\xff\xfe\xc2\xa90123456"
        );
    }

    #[test]
    fn write_data_large() {
        let mut wrtr = writer();
        let buf = vec![0xff; 65536];
        let expected: [&[u8]; 4] = [b"fff0", &buf[0..65516], b"0018", &buf[65516..65536]];
        let expected = expected.concat();
        wrtr.write(&buf).unwrap();
        wrtr.flush().unwrap();
        assert_eq!(expected, wrtr.writer.into_inner());
    }
}

#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::match_like_matches_macro)]

extern crate bytes;
extern crate clap;
extern crate digest;
extern crate git2;
extern crate hex;
extern crate libc;
extern crate scutiger_core;
extern crate sha2;
extern crate tempfile;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

use bytes::Bytes;
use clap::{App, Arg, ArgMatches};
use digest::Digest;
use git2::Repository;
use scutiger_core::errors::{Error, ErrorKind, ExitStatus};
use scutiger_core::pktline;
use sha2::Sha256;
use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process;
use tempfile::Builder;

struct PktLineHandler<R: io::Read, W: io::Write> {
    rdr: pktline::Reader<R>,
    wrtr: pktline::Writer<W>,
}

impl<R: io::Read, W: io::Write> PktLineHandler<R, W> {
    fn new(rdr: R, wrtr: W) -> Self {
        PktLineHandler {
            rdr: pktline::Reader::new(rdr),
            wrtr: pktline::Writer::new(wrtr),
        }
    }

    fn read_to_type(&mut self, typ: pktline::PacketType) -> Result<Vec<Bytes>, Error> {
        self.rdr
            .iter()
            .take_while(|pkt| match pkt {
                Ok(pkt) if pkt.packet_type() == typ => false,
                _ => true,
            })
            .map(|pkt| pkt.map(|p| p.data().unwrap_or(b"").into()))
            .collect()
    }

    fn read_to_delim(&mut self) -> Result<Vec<Bytes>, Error> {
        self.read_to_type(pktline::PacketType::Delim)
    }

    fn read_to_flush(&mut self) -> Result<Vec<Bytes>, Error> {
        self.read_to_type(pktline::PacketType::Flush)
    }

    fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.wrtr.write_all(msg)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        let pkt = pktline::Packet::new(pktline::PacketType::Flush, b"");
        self.wrtr.write_packet(&pkt)?;
        Ok(())
    }

    fn delim(&mut self) -> Result<(), Error> {
        let pkt = pktline::Packet::new(pktline::PacketType::Delim, b"");
        self.wrtr.write_packet(&pkt)?;
        Ok(())
    }

    fn send_error(&mut self, status: u32, msg: &str) -> Result<(), Error> {
        self.send(format!("status {:03}\n", status).as_bytes())?;
        self.delim()?;
        self.send(msg.as_bytes())?;
        self.flush()?;
        Ok(())
    }

    fn send_status(&mut self, status: Status) -> Result<(), Error> {
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

struct HashingReader<'a, R: io::Read, H: digest::Digest + io::Write> {
    rdr: &'a mut R,
    hash: H,
    size: u64,
}

impl<'a, R: io::Read, H: digest::Digest + io::Write> HashingReader<'a, R, H> {
    fn new(rdr: &'a mut R, hash: H) -> Self {
        HashingReader { rdr, hash, size: 0 }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn oid(self) -> Result<Oid, Error> {
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

struct Status {
    code: u32,
    args: Option<Vec<Bytes>>,
    messages: Option<Vec<Bytes>>,
    reader: Option<Box<io::Read>>,
}

impl Status {
    fn success() -> Status {
        Status {
            code: 200,
            args: None,
            messages: None,
            reader: None,
        }
    }

    fn new_success(messages: Vec<Bytes>) -> Status {
        Status {
            code: 200,
            args: None,
            messages: Some(messages),
            reader: None,
        }
    }

    fn new_reader(args: Vec<Bytes>, reader: Box<io::Read>) -> Status {
        Status {
            code: 200,
            args: Some(args),
            messages: None,
            reader: Some(reader),
        }
    }

    fn new_failure(code: u32, message: &[u8]) -> Status {
        Status {
            code,
            args: None,
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

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct Oid {
    // We hold this value as a string because bytes cannot be converted into paths on Windows.
    oid: String,
}

impl Oid {
    fn new(oid: &[u8]) -> Result<Self, Error> {
        if Self::valid(&oid) {
            // Note that because we've validated that this string contains only lowercase hex
            // characters, this will always be a complete, non-lossy transformation.
            Ok(Oid {
                oid: String::from_utf8_lossy(oid).into(),
            })
        } else {
            Err(Error::new_simple(ErrorKind::InvalidLFSOid))
        }
    }

    fn as_str(&self) -> &str {
        &self.oid
    }

    fn value(&self) -> &[u8] {
        self.oid.as_bytes()
    }

    fn valid(b: &[u8]) -> bool {
        b.len() == 64
            && b.iter()
                .all(|&x| (b'0'..=b'9').contains(&x) || (b'a'..=b'f').contains(&x))
    }

    /// Returns the expected path for this object given the `path` argument, which should be a
    /// `.git/lfs` directory.
    fn expected_path(&self, path: &Path) -> PathBuf {
        let mut buf = path.to_path_buf();
        buf.push("objects");
        buf.push(&self.oid[0..2]);
        buf.push(&self.oid[2..4]);
        buf.push(&self.oid);
        buf
    }

    /// Returns a boolean indicating whether an object with this ID is present under the given
    /// path, which should be a `.git/lfs` directory.
    fn exists_at_path(&self, path: &Path) -> bool {
        self.expected_path(path).is_file()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.oid)
    }
}

struct BatchItem {
    oid: Oid,
    size: u64,
    present: bool,
}

struct Processor<'a, R: io::Read, W: io::Write> {
    handler: PktLineHandler<R, W>,
    lfs_path: &'a Path,
    umask: u32,
}

impl<'a, R: io::Read, W: io::Write> Processor<'a, R, W> {
    fn new(handler: PktLineHandler<R, W>, lfs_path: &'a Path, umask: u32) -> Self {
        Processor {
            handler,
            lfs_path,
            umask,
        }
    }

    fn version(&self) -> Result<Status, Error> {
        Ok(Status::success())
    }

    fn error(&self, code: u32, msg: &str) -> Result<Status, Error> {
        Ok(Status::new_failure(code, msg.as_bytes()))
    }

    fn read_batch(&mut self) -> Result<Vec<BatchItem>, Error> {
        if let Err(e) = self.handler.read_to_delim() {
            return Err(Error::new(ErrorKind::ParseError, Some(e)));
        }
        let data = match self.handler.read_to_flush() {
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        data.iter()
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
                let oid = Oid::new(&pair[0])?;
                let present = oid.exists_at_path(self.lfs_path);
                Ok(BatchItem { oid, size, present })
            })
            .collect::<Result<Vec<_>, Error>>()
    }

    fn batch_data(&mut self, present_action: &str, missing_action: &str) -> Result<Status, Error> {
        let batch = self.read_batch()?;
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
        self.batch_data("noop", "upload")
    }

    fn download_batch(&mut self) -> Result<Status, Error> {
        self.batch_data("download", "noop")
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

    fn put_object(&mut self, oid: &[u8]) -> Result<Status, Error> {
        let oid = Oid::new(oid)?;
        let mut tempdir: PathBuf = self.lfs_path.into();
        tempdir.push("incomplete");
        let mut tempfile = Builder::new()
            .prefix(oid.as_str())
            .rand_bytes(12)
            .tempfile_in(&tempdir)?;
        let expected_size = match self.handler.read_to_delim() {
            Ok(vec) => {
                let prefix: &[u8] = b"size=";
                if vec.len() != 1 {
                    return Err(Error::from_message(
                        ErrorKind::ParseError,
                        "unexpected number of arguments",
                    ));
                }
                let item = &vec[0];
                if item.len() < prefix.len()
                    || &item[0..prefix.len()] != prefix
                    || item[item.len() - 1] != b'\n'
                {
                    return Err(Error::from_message(
                        ErrorKind::ParseError,
                        "unexpected value parsing size header",
                    ));
                }
                let ssize = &item[prefix.len()..item.len() - 1];
                match String::from_utf8_lossy(ssize).parse() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::from_message(
                            ErrorKind::InvalidInteger,
                            format!("unexpected value parsing size header: {:?}", item),
                        ))
                    }
                }
            }
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        let mut rdr = HashingReader::new(&mut self.handler.rdr, Sha256::new());
        io::copy(&mut rdr, tempfile.as_file_mut())?;
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

        // This is a valid file.  Let's create any missing directories and then rename it.  This
        // uses an atomic rename, which should work
        // on all platforms.
        let dest_path = oid.expected_path(self.lfs_path);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        tempfile
            .into_temp_path()
            .persist(&dest_path)
            .map_err(|e| Error::new(ErrorKind::IOError, Some(e)))?;
        self.fix_permissions(&dest_path)
    }

    fn verify_object(&mut self, oid: &[u8], size: Option<&&[u8]>) -> Result<Status, Error> {
        let size = match size {
            Some(v) => v,
            None => return self.error(400, "missing size"),
        };
        match self.handler.read_to_flush() {
            Ok(v) if v.is_empty() => (),
            Ok(_) => {
                return Err(Error::from_message(
                    ErrorKind::ParseError,
                    "unexpected number of arguments",
                ))
            }
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
        let expected_size = match String::from_utf8_lossy(size).parse() {
            Ok(x) => x,
            Err(_) => return Err(Error::new_simple(ErrorKind::InvalidInteger)),
        };
        let oid = Oid::new(oid)?;
        let path = oid.expected_path(&self.lfs_path);
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return self.error(404, "not found"),
            Err(e) => return Err(e.into()),
        };
        let actual_size = metadata.len();
        if actual_size == expected_size {
            Ok(Status::success())
        } else {
            self.error(409, "mismatched size or cryptographic collision")
        }
    }

    fn get_object(&mut self, oid: &[u8]) -> Result<Status, Error> {
        let oid = Oid::new(oid)?;
        let path = oid.expected_path(&self.lfs_path);
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return self.error(404, "not found"),
            Err(e) => return Err(e.into()),
        };
        let metadata = match file.metadata() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return self.error(404, "not found"),
            Err(e) => return Err(e.into()),
        };
        let args = vec![format!("size={}\n", metadata.len()).into()];

        self.handler
            .read_to_flush()
            .map_err(|e| Error::new(ErrorKind::ParseError, Some(e)))?;

        Ok(Status::new_reader(args, Box::new(file)))
    }

    fn process_commands(&mut self, mode: Mode) -> Result<(), Error> {
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
                (b"verify-object", Some(oid), Mode::Upload) => self.verify_object(oid, msgs.get(2)),
                (b"verify-object", Some(_), _) => self.error(403, "not allowed"),
                (b"get-object", Some(oid), Mode::Download) => self.get_object(oid),
                (b"get-object", Some(_), _) => self.error(403, "not allowed"),
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

#[derive(Clone, Copy)]
enum Mode {
    Upload,
    Download,
}

/// The main program.
struct Program<'p> {
    repo: &'p Repository,
    operation: String,
    lfs_path: PathBuf,
    umask: u32,
}

impl<'p> Program<'p> {
    /// Creates a new main program.
    ///
    /// The arguments correspond to the command line options.
    fn new(repo: &'p Repository, operation: String) -> Self {
        let mut lfs_path = repo.path().to_path_buf();
        lfs_path.push("lfs");
        Program {
            repo,
            operation,
            lfs_path,
            umask: 0o077,
        }
    }

    /// Runs this main program and generate a programmatically testable result.
    fn run<R: io::Read, O: io::Write, E: io::Write>(
        &self,
        input: &mut R,
        output: &mut O,
        _error: &mut E,
    ) -> Result<(), Error> {
        self.create_directories()?;
        let mut handler = PktLineHandler::new(input, output);
        self.send_capabilities(&mut handler)?;
        let mut processor = Processor::new(handler, &self.lfs_path, self.umask);
        match self.operation.as_str() {
            "upload" => processor.process_commands(Mode::Upload),
            "download" => processor.process_commands(Mode::Download),
            _ => Err(Error::new_simple(ErrorKind::UnknownCommand)),
        }
    }

    fn send_capabilities<R: io::Read, W: io::Write>(
        &self,
        handler: &mut PktLineHandler<R, W>,
    ) -> Result<(), Error> {
        handler.send(b"version=1\n")?;
        handler.flush()?;
        Ok(())
    }

    fn create_directories(&self) -> Result<(), Error> {
        for dir in &["objects", "incomplete", "tmp"] {
            let mut path = self.lfs_path.clone();
            path.push(dir);
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn set_permissions(&self) -> Result<u32, Error> {
        let config = self.repo.config()?;
        let sval = config.get_string("core.sharedrepository");
        let tval = sval.as_ref().map(|s| s.as_str());
        let perms = match (config.get_bool("core.sharedrepository"), tval) {
            (Ok(true), _) | (_, Ok("group")) => Some(0o660),
            (Ok(false), _) | (_, Ok("umask")) => None,
            (_, Ok("all")) | (_, Ok("world")) | (_, Ok("everybody")) => Some(0o664),
            (_, Ok(x)) if u16::from_str_radix(x, 8).is_ok() => {
                Some(u16::from_str_radix(x, 8).unwrap())
            }
            (_, Err(e)) if e.code() == git2::ErrorCode::NotFound => None,
            (_, Err(e)) => return Err(git2::Error::new(e.code(), e.class(), e.message()).into()),
            _ => None,
        };
        let res = match perms {
            Some(value) => {
                let new = 0o777 & !value as libc::mode_t;
                unsafe { libc::umask(new) };
                new
            }
            None => unsafe {
                let value = libc::umask(0o777);
                libc::umask(value);
                value
            },
        };
        Ok(res as u32)
    }

    #[cfg(not(unix))]
    fn set_permissions(&self) -> Result<(), Error> {
        Ok(())
    }

    fn main_internal<R: io::Read, O: io::Write, E: io::Write>(
        &mut self,
        input: &mut R,
        output: &mut O,
        error: &mut E,
    ) -> Result<(), Error> {
        self.umask = self.set_permissions()?;
        self.run(input, output, error)
    }

    /// Runs this main program and generate output and error codes.
    ///
    /// The program is run (as per `run`) with the specified output and error streams
    /// (corresponding logically to standard output and standard error) and returns an exit code.
    /// For programmatic execution, see `run`.
    fn main<R: io::Read, O: io::Write, E: io::Write>(
        &mut self,
        input: &mut R,
        output: &mut O,
        error: &mut E,
    ) -> i32 {
        match self.main_internal(input, output, error) {
            Ok(()) => ExitStatus::Success as i32,
            Err(e) => {
                writeln!(error, "{}", e).unwrap();
                e.exit_status() as i32
            }
        }
    }
}

fn parse_options<'a>() -> App<'a, 'a> {
    App::new("git-lfs-transfer")
        .about("Implement the remote side of a Git LFS SSH transfer")
        .arg(Arg::with_name("path").required(true))
        .arg(Arg::with_name("operation").required(true))
}

fn program<'a>(r: &'a Repository, matches: &'a ArgMatches) -> Program<'a> {
    Program::new(r, matches.value_of("operation").unwrap().into())
}

fn repo<P: AsRef<Path>>(path: P) -> Repository {
    let repo = git2::Repository::discover(path);
    match repo {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(4);
        }
    }
}

fn setup() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() {
    setup();
    let app = parse_options();
    let matches = app.get_matches();
    let path = matches.value_of_os("path").unwrap();
    let r = repo(path);
    let mut prog = program(&r, &matches);
    process::exit(prog.main(&mut io::stdin(), &mut io::stdout(), &mut io::stderr()));
}

#[cfg(test)]
mod tests {
    use super::{Error, Program};
    use git2::Repository;
    use std::fs;
    use std::io;
    use std::io::Read;
    use std::path::PathBuf;

    pub struct TestRepository {
        pub repo: Repository,
        pub tempdir: tempfile::TempDir,
    }

    impl TestRepository {
        pub fn new() -> TestRepository {
            let dir = tempfile::tempdir().unwrap();
            let repo = Repository::init(dir.path()).unwrap();
            TestRepository { repo, tempdir: dir }
        }
    }

    fn run(
        fixtures: &TestRepository,
        operation: &str,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut input = io::Cursor::new(transcript);
        let mut output = io::Cursor::new(Vec::new());
        let mut error = io::Cursor::new(Vec::new());
        Program::new(&fixtures.repo, operation.into()).run(&mut input, &mut output, &mut error)?;
        Ok(output.into_inner())
    }

    fn assert_file(fixtures: &TestRepository, name: &str, contents: &[u8]) {
        let mut path: PathBuf = fixtures.repo.path().into();
        path.push("lfs");
        path.push("objects");
        path.push(name);
        let file = fs::File::open(&path).unwrap();
        let bytes = file
            .bytes()
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        assert_eq!(bytes, contents);
    }

    fn refute_file(fixtures: &TestRepository, name: &str) {
        let mut path: PathBuf = fixtures.repo.path().into();
        path.push("lfs");
        path.push("objects");
        path.push(name);
        fs::metadata(&path).unwrap_err();
    }

    #[test]
    fn failed_verify() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000055verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 409
0001002emismatched size or cryptographic collision0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn missing_object() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000055verify-object 0000000000000000000000000000000000000000000000000000000000000000 5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 404
0001000dnot found0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_upload() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000055verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
00000056verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        assert_file(
            &fixtures,
            "6c/a1/6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            b"abc123",
        );
        assert_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
            b"This is\x00a complicated\xc2\xa9message.\n",
        );
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000000fstatus 200
0000000fstatus 200
0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_download() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000056verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000";
        assert_eq!(result, expected);

        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050get-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
0000";
        let result = run(&fixtures, "download", message).unwrap();
        assert_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
            b"This is\x00a complicated\xc2\xa9message.\n",
        );
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004c6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 noop
0051ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 download
0000000fstatus 200
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn invalid_upload() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x01a complicated\xc2\xa9message.
00000055verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
00000056verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        // This file was correct.
        assert_file(
            &fixtures,
            "6c/a1/6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            b"abc123",
        );
        // We didn't write this file because it was corrupt.
        refute_file(
            &fixtures,
            "ce/08/ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626",
        );
        // We didn't write this one, either, because nobody asked us to.
        refute_file(
            &fixtures,
            "36/79/367988c7cb91e13beda0a15fb271afcbf02fa7a0e75d9e25ac50b2b4b38af5f5",
        );

        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
0000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 400
000100acerror: corrupt data: expected oid ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626, got 367988c7cb91e13beda0a15fb271afcbf02fa7a0e75d9e25ac50b2b4b38af5f50000000fstatus 200
0000000fstatus 404
0001000dnot found0000";
        assert_eq!(result, expected);
    }
}

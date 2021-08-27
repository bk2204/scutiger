#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::mutable_key_type)]

extern crate bytes;
extern crate chrono;
extern crate clap;
extern crate digest;
extern crate git2;
extern crate hex;
extern crate libc;
extern crate scutiger_core;
extern crate scutiger_lfs;
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
use scutiger_lfs::backend::local::LocalBackend;
use scutiger_lfs::backend::Backend;
use scutiger_lfs::processor::{
    ArgumentParser, BatchItem, HashingReader, Mode, Oid, PktLineHandler, Status,
};
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;

struct Processor<'a, R: io::Read, W: io::Write> {
    handler: PktLineHandler<R, W>,
    lfs_path: &'a Path,
    umask: u32,
    timestamp: Option<i64>,
    backend: Box<dyn Backend + 'a>,
}

impl<'a, R: io::Read, W: io::Write> Processor<'a, R, W> {
    fn new(
        handler: PktLineHandler<R, W>,
        lfs_path: &'a Path,
        umask: u32,
        timestamp: Option<i64>,
    ) -> Self {
        Processor {
            handler,
            lfs_path,
            umask,
            timestamp,
            backend: Box::new(LocalBackend::new(lfs_path, umask, timestamp)),
        }
    }

    fn version(&mut self) -> Result<Status, Error> {
        self.handler.read_to_flush()?;
        Ok(Status::new_success(vec![]))
    }

    fn error(&self, code: u32, msg: &str) -> Result<Status, Error> {
        Ok(Status::new_failure(code, msg.as_bytes()))
    }

    fn read_batch(&mut self, mode: Mode) -> Result<Vec<BatchItem>, Error> {
        if let Err(e) = self.handler.read_to_delim() {
            return Err(Error::new(ErrorKind::ParseError, Some(e)));
        }
        let data = match self.handler.read_to_flush() {
            Ok(v) => v,
            Err(e) => return Err(Error::new(ErrorKind::ParseError, Some(e))),
        };
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
            Err(e) => return Err(e.into()),
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
            let (ok, lock) = match lock_backend.create(&path) {
                Ok(l) => (true, l),
                Err(e) if e.kind() == ErrorKind::Conflict => match lock_backend.from_path(&path) {
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
            .map(|x| ArgumentParser::parse_integer(x))
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
        timestamp: Option<i64>,
    ) -> Result<(), Error> {
        self.create_directories()?;
        let mut handler = PktLineHandler::new(input, output);
        self.send_capabilities(&mut handler)?;
        let mut processor = Processor::new(handler, &self.lfs_path, self.umask, timestamp);
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
        for dir in &["objects", "incomplete", "tmp", "locks"] {
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
    fn set_permissions(&self) -> Result<u32, Error> {
        Ok(0o077)
    }

    fn main_internal<R: io::Read, O: io::Write, E: io::Write>(
        &mut self,
        input: &mut R,
        output: &mut O,
        error: &mut E,
    ) -> Result<(), Error> {
        self.umask = self.set_permissions()?;
        self.run(input, output, error, None)
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
    let repo = git2::Repository::open(path);
    match repo {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(4);
        }
    }
}

#[cfg(unix)]
fn setup() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn setup() {}

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
        Program::new(&fixtures.repo, operation.into()).run(
            &mut input,
            &mut output,
            &mut error,
            Some(1000684800),
        )?;
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

    #[cfg(windows)]
    fn username() -> String {
        "unknown".into()
    }

    #[cfg(unix)]
    fn username() -> String {
        format!("uid {}", unsafe { libc::getuid() })
    }

    fn replace_user_id(transcript: &str) -> String {
        let name = username();
        transcript.replace(
            "0018ownername=test user\n",
            &format!(
                "{:04x}ownername={}\n",
                4 + "ownername=\n".len() + name.len(),
                name
            ),
        ).replace(
            "0059ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 test user\n",
            &format!(
                "{:04x}ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 {}\n",
                4 + "ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 \n".len() + name.len(),
                name
            ),
        )
    }

    #[test]
    fn failed_verify() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
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
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 0000000000000000000000000000000000000000000000000000000000000000
000bsize=5
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
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
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
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
00010000000fstatus 200
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
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x00a complicated\xc2\xa9message.
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &[u8] = b"000eversion=1
0000000fstatus 200
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 200
0000";
        assert_eq!(result, expected);

        let message = b"000eversion 1
0000000abatch
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
00010000000fstatus 200
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
0000000abatch
0011transfer=ssh
001crefname=refs/heads/main
000100476ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6
0048ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32
00000050put-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
0001000aabc12300000050put-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
00010024This is\x01a complicated\xc2\xa9message.
00000053verify-object 6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090
000bsize=6
00000053verify-object ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626
000csize=32
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
00010000000fstatus 200
0001004e6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090 6 upload
004fce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626 32 upload
0000000fstatus 200
0000000fstatus 400
000100acerror: corrupt data: expected oid ce08b837fe0c499d48935175ddce784e8c372d3cfb1c574fe1caff605d4f0626, got 367988c7cb91e13beda0a15fb271afcbf02fa7a0e75d9e25ac50b2b4b38af5f50000000fstatus 200
0000000fstatus 404
0001000dnot found0000";
        assert_eq!(result, expected);
    }

    #[test]
    fn simple_locking() {
        let fixtures = TestRepository::new();
        let message = b"000eversion 1
00000009lock
000dpath=foo
001crefname=refs/heads/main
00000009lock
000dpath=foo
001crefname=refs/heads/main
0000000elist-lock
000elimit=100
0000004cunlock d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
0000";
        let result = run(&fixtures, "upload", message).unwrap();
        let expected: &str = "000eversion=1
0000000fstatus 200
00010000000fstatus 201
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0000000fstatus 409
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0001000cconflict0000000fstatus 200
0001004alock d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
004epath d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 foo
0069locked-at d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 2001-09-17T00:00:00+00:00
0059ownername d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 test user
0050owner d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28 ours
0000000fstatus 200
0048id=d76670443f4d5ecdeea34c12793917498e18e858c6f74cd38c4b794273bb5e28
000dpath=foo
0028locked-at=2001-09-17T00:00:00+00:00
0018ownername=test user
0000";
        let expected = replace_user_id(expected);
        assert_eq!(result, expected.as_bytes());
    }
}

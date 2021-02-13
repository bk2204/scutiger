use super::Error;
use git2::Repository;
use std::env;
use std::ffi::OsString;
use std::io;
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};

pub struct Pager {
    process: Option<Child>,
}

impl Pager {
    pub fn new(repo: &Repository) -> Result<Self, Error> {
        let pager: Result<Option<Child>, _> = Self::find_pager(repo)
            .map(|pager| {
                Command::new("sh")
                    .arg("-c")
                    .arg(pager)
                    .stdin(Stdio::piped())
                    .spawn()
            })
            .transpose();
        Ok(Pager { process: pager? })
    }

    fn find_pager(repo: &Repository) -> Option<OsString> {
        if unsafe { libc::isatty(io::stdout().as_raw_fd()) } != 1 {
            return None;
        }
        let core_pager: Option<OsString> = repo
            .config()
            .ok()
            .and_then(|config| config.get_path("core.pager").ok().map(|val| val.into()));
        let pager: OsString = env::var_os("GIT_PAGER")
            .or(core_pager)
            .or_else(|| env::var_os("PAGER"))
            .unwrap_or_else(|| "less".into());
        if pager == "cat" {
            None
        } else {
            Some(pager)
        }
    }

    pub fn stdout<'a>(&'a mut self) -> Box<io::Write + 'a> {
        self.process
            .as_mut()
            .and_then(|p| {
                let x: Box<io::Write> = Box::new(p.stdin.as_mut()?);
                Some(x)
            })
            .unwrap_or_else(|| Box::new(io::stdout()))
    }
}

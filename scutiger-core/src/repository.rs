use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use thiserror::Error as ErrorTrait;

/// A simple repository.
#[derive(Clone)]
pub struct Repository {
    limited: bool,
    git_dir: PathBuf,
}

impl Repository {
    /// Discover an existing repository starting at `path`.
    ///
    /// If `limited` is true, this command is limited to finding repository paths and reading
    /// configuration, and can operate in a repository of any ownership.  Otherwise, it is
    /// unrestricted, but cannot operate across users.
    pub fn discover<P: AsRef<Path>>(path: P, limited: bool) -> Result<Repository, Error> {
        let p = path
            .as_ref()
            .canonicalize()
            .map_err(Error::PathCanonicalizationFailure)?;
        let args: &[&str] = if limited {
            &["-c", "safe.directory=*", "rev-parse", "--absolute-git-dir"]
        } else {
            &["rev-parse", "--absolute-git-dir"]
        };
        let git_dir = match Self::run_git(args, p) {
            Ok(output) => match output.status.code() {
                Some(0) => {
                    let data = &output.stdout;
                    let data = if let Some(b'\n') = data.last() {
                        &data[0..data.len() - 1]
                    } else {
                        data
                    };
                    Self::os_string_from_bytes(data)
                }
                _ => {
                    return Err(Error::GitFatalError(
                        String::from_utf8_lossy(&output.stderr).to_string(),
                    ))
                }
            },
            Err(e) => return Err(e),
        };
        Ok(Repository {
            limited,
            git_dir: git_dir.into(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.git_dir
    }

    pub fn config(&self) -> Result<Config, Error> {
        let args: &[&str] = if self.limited {
            &["-c", "safe.directory=*", "config", "-l"]
        } else {
            &["config", "-l"]
        };
        match Self::run_git(args, &self.git_dir) {
            Ok(output) => match output.status.code() {
                Some(0) => Ok(Config::new(&output.stdout)),
                _ => Err(Error::GitFatalError(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                )),
            },
            Err(e) => Err(e),
        }
    }

    fn run_git<P: AsRef<Path>>(args: &[&str], cwd: P) -> Result<Output, Error> {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .map_err(Error::SpawnFailure)
    }

    #[cfg(windows)]
    fn os_string_from_bytes(bytes: &[u8]) -> OsString {
        String::from_utf8_lossy(bytes).to_string().into()
    }

    #[cfg(unix)]
    fn os_string_from_bytes(bytes: &[u8]) -> OsString {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        OsStr::from_bytes(bytes).to_owned()
    }
}

#[derive(Debug, ErrorTrait)]
pub enum Error {
    #[error("failed to spawn git: {0}")]
    SpawnFailure(io::Error),
    #[error("git: {0}")]
    GitFatalError(String),
    #[error("failed to find repository: {0}")]
    PathCanonicalizationFailure(io::Error),
    #[error("not allowed in untrusted repositories")]
    DisallowedAction,
}

pub struct Config {
    data: BTreeMap<String, Vec<String>>,
}

impl Config {
    fn new(config: &[u8]) -> Config {
        let mut data = BTreeMap::new();
        let mut last_key = None;
        for line in config.split(|b| *b == b'\n') {
            let mut pieces = line.splitn(2, |b| *b == b'=');
            let (first, second) = (pieces.next(), pieces.next());
            match (first, second, last_key.as_deref()) {
                (Some(key), Some(value), _) => {
                    let key = String::from_utf8_lossy(key).to_string();
                    let value = String::from_utf8_lossy(value).to_string();
                    let v: &mut Vec<_> = data.entry(key.clone()).or_default();
                    v.push(value);
                    last_key = Some(key);
                }
                (Some(b""), None, _) => break,
                (Some(remainder), None, Some(key)) => {
                    let remainder = String::from_utf8_lossy(remainder).to_string();
                    if let Some(entry) = data.get_mut(key).and_then(|v| v.last_mut()) {
                        *entry += "\n";
                        *entry += &remainder;
                    }
                }
                (Some(_), None, None) => (),
                (None, None, _) => break,
                (None, Some(_), _) => unreachable!(),
            }
        }
        Config { data }
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.data
            .get(key)
            .and_then(|v| v.last())
            .map(|s| s.as_str())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.data
            .get(key)
            .and_then(|v| v.last())
            .and_then(|s| match &**s {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::collections::BTreeMap;

    #[test]
    fn config_parsing() {
        let mut expected = BTreeMap::new();
        expected.insert("core.bare".to_string(), vec!["false".to_string()]);
        expected.insert(
            "core.repositoryformatversion".to_string(),
            vec!["0".to_string()],
        );
        expected.insert(
            "credential.helper".to_string(),
            vec!["abc".to_string(), "123".to_string()],
        );
        expected.insert("alias.mark".to_string(), vec![r#"!f() { local m="${1:-$(git rev-parse --abbrev-ref HEAD)}"; git rev-parse --verify ":/^:$m
"; };f"#.to_string()]);

        let data = br#"credential.helper=abc
alias.mark=!f() { local m="${1:-$(git rev-parse --abbrev-ref HEAD)}"; git rev-parse --verify ":/^:$m
"; };f
credential.helper=123
core.repositoryformatversion=0
core.bare=false
"#;

        let cfg = Config::new(data);
        assert_eq!(cfg.data, expected);
        assert_eq!(cfg.get_bool("core.bare"), Some(false));
        assert_eq!(cfg.get_string("core.bare"), Some("false"));
        assert_eq!(cfg.get_bool("core.repositoryformatversion"), None);
    }
}

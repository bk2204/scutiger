use git2::{Repository, RepositoryInitOptions};
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile;

const FIXTURE_PATH: &'static str = "src/bin/fixtures/fixtures/test-repo";

/// A temporary repository that provides a fixed set of fixtures.
pub struct TestRepository {
    pub repo: Repository,
    pub tempdir: tempfile::TempDir,
}

impl TestRepository {
    /// Create a new test repository. If the repository cannot be created, panic.
    pub fn new() -> TestRepository {
        let dir = tempfile::tempdir().unwrap();
        let mut opts = RepositoryInitOptions::new();
        opts.initial_head("refs/heads/dev");
        let repo = Repository::init_opts(dir.path(), &opts).unwrap();

        let mut fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixtures.push(FIXTURE_PATH);
        let fixtures = File::open(fixtures).unwrap();
        let mut child = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .arg("fast-import")
            .stdin(fixtures)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.wait().unwrap();

        TestRepository { repo, tempdir: dir }
    }
}

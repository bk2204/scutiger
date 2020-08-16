use libc::c_int;

pub const GIT_OPT_ENABLE_STRICT_HASH_VERIFICATION: c_int = 22;

extern "C" {
    pub fn git_libgit2_opts(key: c_int, ...) -> c_int;
}

pub fn init() {
    unsafe {
        // We turn off hashing all of the data because we assume we are working with an intact
        // repository that has already been checked when downloaded. Furthermore, the performance
        // penalty for hashing objects we already have is quite significant and adds approximately
        // 33% onto the time it takes git-at to run.
        git_libgit2_opts(GIT_OPT_ENABLE_STRICT_HASH_VERIFICATION, 0);
    }
}

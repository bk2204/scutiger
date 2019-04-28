DESTDIR ?= /usr/local

MANPAGE_DIR = doc/man

# We are linking libraries written in C which may have suboptimal security
# histories. Prefer dynamic linking so security updates need not require a
# recompile.
DYNAMIC ?= 1

ifeq ($(DYNAMIC),1)
LIBGIT2_SYS_USE_PKG_CONFIG ?= 1
PKG_CONFIG_ALL_DYNAMIC ?= 1

export LIBGIT2_SYS_USE_PKG_CONFIG
export PKG_CONFIG_ALL_DYNAMIC
endif

# Test configuration.
GROUPS := stretch stable nightly
DOCKER_FILES := $(patsubst %,test/Dockerfile.%,$(GROUPS))
DOCKER_STAMPS := $(patsubst %,test/Dockerfile.%.stamp,$(GROUPS))
CI_TARGETS := $(patsubst %,ci-%,$(GROUPS))
INCLUDES := $(wildcard test/include/*.erb)

SRC := $(shell find . -name '*.rs') Makefile Cargo.toml

all:
	cargo build --release

test:
	cargo test

install: all
	for i in target/release/git-*; do \
		[ -x "$$i" ] || continue; \
		install -m 755 "$$i" "$(DESTDIR)/bin/$$(basename "$$i")"; \
	done

clean:
	cargo clean
	rm -fr target tmp
	for i in "$(DOCKER_STAMPS)"; \
	do \
		[ ! -f "$$i" ] || docker image rm -f "$$i"; \
	done
	rm -f $(DOCKER_FILES) $(DOCKER_STAMPS)
	rm -fr tmp

linkage: tmp
	set -e; \
	for i in target/release/git-*; \
	do \
		echo $$i | grep -vF '.d' || continue; \
		lfile=tmp/$$(basename $$i)-linkage; \
		ldd $$i | tee $$lfile; \
		echo Ensuring libssl is absent; \
		grep -qsv libssl $$lfile; \
		echo Looking for libgit2; \
		grep -qs libgit2 $$lfile; \
		echo Looking for libz; \
		grep -qs libz $$lfile; \
		echo Looking for libpcre2; \
		grep -qs libpcre2 $$lfile; \
	done

tmp:
	[ -d tmp ] || mkdir tmp

# We do not require both of these commands here since nightly Rust may be
# missing one or more of these. When run under CI, they should be present for
# stable Rust and catch any issues.
#
# Note if we're using rustup, cargo-clippy may exist in the PATH even if clippy
# isn't installed, but it may be a wrapper that just fails when invoked. Check
# that it can successfully print help output to check if we really have clippy.
lint:
	if command -v cargo-clippy && cargo-clippy --help >/dev/null 2>&1; \
	then \
		$(MAKE) clippy; \
	fi
	if command -v rustfmt; \
	then \
		$(MAKE) fmt; \
	fi

ci: $(CI_TARGETS)

ci-%: test/Dockerfile.%.stamp
	docker run --rm $$(cat "$<") \
		sh -c 'cd /usr/src/scutiger && make all && make test && make lint'

test/Dockerfile.%.stamp: test/Dockerfile.% $(SRC)
	docker build --iidfile="$@" -f "$<" .

test/Dockerfile.%: test/Dockerfile.%.erb $(INCLUDES)
	test/template "$<" >"$@"

clippy:
	rm -rf target
	cargo clippy -- -D warnings

fmt:
	if rustfmt --help | grep -qse --check; \
	then \
		rustfmt --check $$(find . -name '*.rs'); \
	else \
		rustfmt --write-mode diff $$(find . -name '*.rs'); \
	fi

.PHONY: all lint ci clean doc clippy fmt linkage test

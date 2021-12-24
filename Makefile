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
GROUPS := stretch buster stable nightly
CRATES := core bin lfs
DOCKER_FILES := $(patsubst %,test/Dockerfile.%,$(GROUPS))
DOCKER_STAMPS := $(patsubst %,test/Dockerfile.%.stamp,$(GROUPS))
CI_TARGETS := $(patsubst %,ci-%,$(GROUPS))
PACKAGE_TARGETS := $(patsubst %,package-%,$(CRATES))
INCLUDES := $(wildcard test/include/*.erb)
MANPAGES := $(patsubst %.adoc,%.1,$(wildcard doc/man/*.adoc))

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

%.md: %.adoc
	asciidoctor -o $@+ -b docbook5 $^
	pandoc -f docbook -t commonmark -o $@ $@+
	$(RM) $@+

%.1: %.adoc
	asciidoctor -b manpage -a compat-mode -o $@ $^

doc: $(MANPAGES)

clean:
	cargo clean
	rm -fr target tmp
	for i in "$(DOCKER_STAMPS)"; \
	do \
		[ ! -f "$$i" ] || docker image rm -f "$$i"; \
	done
	rm -f $(DOCKER_FILES) $(DOCKER_STAMPS)
	rm -fr tmp
	rm -fr *.md *.md+ scutiger-*/*.md scutiger-*/*.md+
	rm -fr doc/man/*.1

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
# The same goes for rustfmt.
lint:
	if command -v cargo-clippy && cargo-clippy --help >/dev/null 2>&1; \
	then \
		$(MAKE) clippy; \
	fi
	if command -v rustfmt && rustfmt --help >/dev/null 2>&1; \
	then \
		$(MAKE) fmt; \
	fi

package: $(PACKAGE_TARGETS)

package-%: scutiger-% scutiger-%/README.md
	(cd "$<" && cargo package --allow-dirty)

ci: $(CI_TARGETS)

ci-%: test/Dockerfile.%.stamp
	docker run --rm \
        -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
        $$(cat "$<") \
		sh -c 'cd /usr/src/scutiger && make test-full'

test-full:
	make all
	make doc
	make test
	make lint

test/Dockerfile.%.stamp: test/Dockerfile.% $(SRC)
	docker build --iidfile="$@" -f "$<" .

test/Dockerfile.%: test/Dockerfile.%.erb $(INCLUDES)
	test/template "$<" >"$@"

clippy:
	rm -rf target
	@# We exclude these lints here instead of in the file because Rust 1.24
	@# doesn't support excluding clippy warnings.  Similarly, it doesn't support
	@# the syntax these lints suggest.
	cargo clippy -- \
		-A clippy::range-plus-one \
		-A clippy::needless-lifetimes \
		-A clippy::unknown-clippy-lints \
		-D warnings

fmt:
	if rustfmt --help | grep -qse --check; \
	then \
		rustfmt --check $$(find . -name '*.rs' | grep -v '^./target'); \
	else \
		rustfmt --write-mode diff $$(find . -name '*.rs' | grep -v '^./target'); \
	fi

.PHONY: all lint ci clean doc clippy fmt linkage test

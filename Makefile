# wiremand Makefile
#
# This Makefile facilitates release binary configs only — it has no debug
# target and every target builds a `-c release` binary. The `install` and
# `update` targets delegate to the binary's own `install`/`update`
# subcommands, which are the single source of truth for host mutations
# (writing /opt/wiremand, systemd units, sudoers, certs).
#
# Usage:
#   make                    build the release binary
#   make install            build + `sudo <bin> install` (full host setup)
#   make update             build + `sudo <bin> update` (replace /opt/wiremand, restart service)
#   make clean              remove build artifacts
#
# Overrides:
#   SWIFT=path/to/swift     swift toolchain binary (default: swift on PATH)
#   JOBS=N                  build parallelism (default: core count)
#   SUDO=                   empty string to skip sudo (run as root)
#
# NOTE: the `install` and `update` subcommands require root — enforced inside
# the binary (`getCurrentUser() == "root"` guard in CLI/Installer.swift). The
# Makefile runs them through sudo unless already root. The binary copies argv[0]
# to /opt/wiremand, so the build product must not be moved before these run.

SWIFT ?= swift
JOBS  ?= $(shell nproc 2>/dev/null || echo 4)
BIN   := .build/release/wiremand
SUDO  ?= sudo

.PHONY: all release install update clean

all: release

release:
	$(SWIFT) build -c release -j $(JOBS)

install: release
	$(SUDO) $(BIN) install

update: release
	$(SUDO) $(BIN) update

clean:
	$(SWIFT) package clean

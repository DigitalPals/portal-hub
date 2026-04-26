# Changelog

## 0.5.0-beta.5 - 2026-04-26

- Replaced live log output-limit termination with a bounded moving replay log
  window so heavy-output sessions keep running.
- Lowered the default replay log retention cap from 64 MiB to 16 MiB.
- Added an internal recorder path that keeps live log compaction active inside
  detached `dtach` sessions.

## 0.5.0-beta.4 - 2026-04-26

- Forward terminal resize notifications through `dtach` attachments so Portal
  Proxy sessions update the remote shell size after the Portal window changes.

## 0.5.0-beta.1 - 2026-04-25

- Added versioned `list --format v1` API.
- Added `version --json` compatibility endpoint.
- Added metadata `schema_version`.
- Added `doctor` health checks.
- Added `prune` for old sessions and ended-session logs.
- Added live log output limit using `script --output-limit`.
- Added optional logging disable mode.
- Added optional target allowlist with exact, wildcard, and IP CIDR patterns.
- Added CLI and SSH lifecycle integration tests.
- Added deployment docs, security policy, examples, release workflow, and CI.
- Added Debian/Ubuntu LXC installer script for release installs and updates.

## 0.2.0

- Prepared the project for public alpha distribution.
- Added initial versioned API, operational commands, retention docs, and CI.

## 0.1.0

- Initial Portal Proxy prototype using OpenSSH, `dtach`, and `script`.
- Supported persistent SSH terminal sessions, reconnect replay, active session
  listing, and thumbnails.

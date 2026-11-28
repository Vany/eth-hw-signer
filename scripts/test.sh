#!/bin/sh
# cargo test the way CI runs it.
#
# Some tests check that file permissions are enforced (a mode-000 file is
# unreadable, a read-only directory is unwritable). Root bypasses those
# checks, so the tests refuse to pass as root. In a container that runs as
# root, this script runs the suite as an unprivileged user with the host's
# uid (HOST_UID/HOST_GID, default 1001: the GitHub runner), then runs the one
# root-only test (`other_owner_file_is_refused_as_root`) as root.
set -eu
if [ "$(id -u)" != 0 ]; then
  exec cargo test --workspace --locked "$@"
fi
uid=${HOST_UID:-1001}
gid=${HOST_GID:-$uid}
getent group "$gid" >/dev/null || groupadd -g "$gid" tester
getent passwd "$uid" >/dev/null || useradd -m -o -u "$uid" -g "$gid" tester
user=$(getent passwd "$uid" | cut -d: -f1)
for d in "$PWD" "${CARGO_TARGET_DIR:-}" "${CARGO_HOME:-/usr/local/cargo}/registry"; do
  [ -n "$d" ] && [ -e "$d" ] && chown -R "$uid:$gid" "$d"
done
runuser -u "$user" -- env HOME="$(getent passwd "$uid" | cut -d: -f6)" \
  cargo test --workspace --locked "$@"
cargo test --workspace --locked -- --ignored other_owner

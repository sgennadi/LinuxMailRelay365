#!/usr/bin/env bash
# LinuxMailRelay365: root-only, verified configuration snapshots and rollback.
# Backup archives may contain private keys and MUST never be copied to the GUI.
set -Eeuo pipefail
umask 077
BASE=/var/backups/linuxmailrelay365
TRANSPORT=/usr/local/libexec/m365_xoauth2_transport.py

usage() { echo 'Usage: recovery.sh --backup | --list | --verify ID | --restore ID | --self-test'; }
valid_id() { [[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]]; }
need_root() {
  [ "$(id -u)" -eq 0 ] || { echo 'Root privileges required for recovery.' >&2; exit 1; }
}
state_value() {
  local value
  value="$(grep -m 1 "^$1=" "$2" | cut -d= -f2 || true)"
  if [ "$value" != yes ] && [ "$value" != no ]; then
    echo "Invalid backup metadata: $1" >&2
    return 1
  fi
  echo "$value"
}
verify() {
  local id="$1" dir="$BASE/$1" key
  if ! valid_id "$id" || [ ! -d "$dir" ] || [ -L "$dir" ]; then
    echo 'Backup ID not found or not valid.' >&2; return 2
  fi
  if [ ! -f "$dir/config.tar.gz" ] || [ -L "$dir/config.tar.gz" ] ||
     [ ! -f "$dir/SHA256SUMS" ] || [ -L "$dir/SHA256SUMS" ] ||
     [ ! -f "$dir/state.txt" ] || [ -L "$dir/state.txt" ]; then
    echo 'Incomplete backup; refusing recovery.' >&2; return 1
  fi
  ( cd "$dir" && sha256sum --status -c SHA256SUMS ) || {
    echo 'Backup SHA256 verification failed.' >&2; return 1
  }
  tar -tzf "$dir/config.tar.gz" >/dev/null || return 1
  for key in postfix_present transport_present service_active service_enabled; do
    state_value "$key" "$dir/state.txt" >/dev/null || return 1
  done
}
backup() {
  need_root
  if [ -L "$BASE" ] || [ -L /etc/postfix ] || [ -L "$TRANSPORT" ]; then
    echo 'Symlinked backup or config path; refusing snapshot.' >&2; return 1
  fi
  install -d -o root -g root -m 0700 "$BASE"
  local id staging active=no enabled=no
  id="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  staging="$(mktemp -d "$BASE/.pending.XXXXXXXX")"
  : > "$staging/files.txt"
  if [ -d /etc/postfix ]; then
    echo 'etc/postfix' >> "$staging/files.txt"
    echo 'postfix_present=yes' > "$staging/state.txt"
  else
    echo 'postfix_present=no' > "$staging/state.txt"
  fi
  if [ -f "$TRANSPORT" ]; then
    echo 'usr/local/libexec/m365_xoauth2_transport.py' >> "$staging/files.txt"
    echo 'transport_present=yes' >> "$staging/state.txt"
  else
    echo 'transport_present=no' >> "$staging/state.txt"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet postfix 2>/dev/null; then active=yes; fi
    if systemctl is-enabled --quiet postfix 2>/dev/null; then enabled=yes; fi
  fi
  echo "service_active=$active" >> "$staging/state.txt"
  echo "service_enabled=$enabled" >> "$staging/state.txt"
  if ! tar --acls --xattrs --numeric-owner -C / -czpf "$staging/config.tar.gz" -T "$staging/files.txt"; then
    rm -rf -- "$staging"; return 1
  fi
  if ! ( cd "$staging" && sha256sum config.tar.gz state.txt > SHA256SUMS &&
         sha256sum --status -c SHA256SUMS &&
         tar -tzf config.tar.gz >/dev/null ); then
    rm -rf -- "$staging"
    echo 'Snapshot verification failed; no configuration change permitted.' >&2
    return 1
  fi
  rm -f -- "$staging/files.txt"
  chmod 0700 "$staging"
  if ! mv -T -- "$staging" "$BASE/$id"; then
    rm -rf -- "$staging"; return 1
  fi
  printf 'BACKUP_ID=%s\nBACKUP_STATUS=verified\n' "$id"
}
restore_snapshot() {
  local id="$1" dir="$BASE/$1" postfix_present transport_present active enabled
  verify "$id" || return 1
  postfix_present="$(state_value postfix_present "$dir/state.txt")"
  transport_present="$(state_value transport_present "$dir/state.txt")"
  active="$(state_value service_active "$dir/state.txt")"
  enabled="$(state_value service_enabled "$dir/state.txt")"
  if [ -L /etc/postfix ]; then
    echo 'Current /etc/postfix is a symlink; refusing unsafe restore.' >&2; return 1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop postfix 2>/dev/null || true
  fi
  if [ -d /etc/postfix ]; then rm -rf -- /etc/postfix; fi
  if [ -e "$TRANSPORT" ] || [ -L "$TRANSPORT" ]; then rm -f -- "$TRANSPORT"; fi
  tar --acls --xattrs --numeric-owner -C / -xzpf "$dir/config.tar.gz" || return 1
  if [ "$postfix_present" = yes ]; then
    [ -d /etc/postfix ] || return 1
    if command -v postfix >/dev/null 2>&1; then
      postfix check || return 1
    else
      echo 'Postfix package is missing; restoring files cannot reinstall packages.' >&2
      return 1
    fi
  else
    [ ! -e /etc/postfix ] || return 1
  fi
  if [ "$transport_present" = yes ]; then
    [ -f "$TRANSPORT" ] || return 1
  else
    [ ! -e "$TRANSPORT" ] || return 1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if [ "$enabled" = yes ]; then
      systemctl enable postfix 2>/dev/null || true
    else
      systemctl disable postfix 2>/dev/null || true
    fi
    if [ "$active" = yes ]; then
      systemctl start postfix || return 1
    else
      systemctl stop postfix 2>/dev/null || true
    fi
  elif [ "$active" = yes ] && command -v postfix >/dev/null 2>&1; then
    postfix start || return 1
  fi
}
restore() {
  need_root
  local selected="$1" emergency
  verify "$selected" || return 1
  emergency="$(backup | sed -n 's/^BACKUP_ID=//p')"
  if ! valid_id "$emergency"; then
    echo 'Pre-restore safety snapshot not created; aborting.' >&2; return 1
  fi
  printf 'PRE_RESTORE_BACKUP_ID=%s\n' "$emergency"
  if restore_snapshot "$selected"; then
    printf 'RESTORED_BACKUP_ID=%s\n' "$selected"
    echo 'Files and service state restored. Package changes are NOT rolled back.'
  else
    echo 'Restore failed. Attempting automatic rollback.' >&2
    if restore_snapshot "$emergency"; then
      echo 'Pre-restore state recovered.' >&2
    else
      echo 'CRITICAL: automatic rollback also failed; manual repair required.' >&2
    fi
    return 1
  fi
}
list_backups() {
  need_root
  local dir id count=0
  [ -d "$BASE" ] || { echo 'BACKUP_COUNT=0'; return 0; }
  for dir in "$BASE"/*; do
    [ -d "$dir" ] || continue
    id="$(basename "$dir")"
    if valid_id "$id"; then
      if verify "$id" >/dev/null 2>&1; then
        printf 'BACKUP_ID=%s\n' "$id"
        count=$((count+1))
      else
        printf 'BACKUP_INVALID_ID=%s\n' "$id"
      fi
    fi
  done
  printf 'BACKUP_COUNT=%s\n' "$count"
}
case "$#" in 0) usage >&2; exit 2;; esac
case "$1" in
  --backup) [ "$#" -eq 1 ] || exit 2; backup ;;
  --list) [ "$#" -eq 1 ] || exit 2; list_backups ;;
  --verify) [ "$#" -eq 2 ] || exit 2; need_root; verify "$2" && echo 'BACKUP_STATUS=verified' ;;
  --restore) [ "$#" -eq 2 ] || exit 2; restore "$2" ;;
  --self-test)
    [ "$#" -eq 1 ] || exit 2
    valid_id '20261117T230101Z-abcdef012345' &&
      ! valid_id '../passwd' && ! valid_id '20261117T230101Z-abcdef012345/../../etc' &&
      echo 'Recovery input validation OK' ;;
  --help|-h) usage ;;
  *) usage >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Verify native Debian Sendmail package config backup, without changing mail.
set -Eeuo pipefail
umask 077
export LC_ALL=C
test "${GITHUB_ACTIONS:-}" = true || { echo "SENDMAIL_BACKUP_LAB_ONLY"; exit 3; }
test -d "${GITHUB_WORKSPACE:-/missing}" || exit 3
test "$(id -u)" -ne 0 || exit 3
! sudo systemctl is-active --quiet sendmail.service || exit 3
! sudo pgrep -x sendmail >/dev/null || exit 3
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 3

# Only hashes are logged. Contents, recipients and credentials stay on Linux.
before="$(sudo find /etc/mail -xdev -type f -exec sha256sum {} + | sha256sum | cut -d " " -f 1)"
test "$before" != "" || exit 3

report="$(sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --backup)"
printf "%s\n" "$report" | grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
id="$(printf "%s\n" "$report" | sed -n 's/^FOREIGN_BACKUP_ID=//p')"
[[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$ ]] || exit 3
sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --verify "$id" |
  grep -Fxq "FOREIGN_BACKUP_STATUS=verified"
comparison="$(sudo python3 linux/foreign-mta-config-backup.py --mta sendmail --preview-recovery "$id")"
printf "%s\n" "$comparison" | grep -Fxq "FOREIGN_BACKUP_CURRENT_CONFIG_MATCH=identical"
test "$(sudo find /etc/mail -xdev -type f -exec sha256sum {} + | sha256sum | cut -d " " -f 1)" = "$before" || {
  echo "SENDMAIL_BACKUP_LAB_SOURCE_MUTATED"; exit 1;
}
! sudo systemctl is-active --quiet sendmail.service || exit 1
! sudo pgrep -x sendmail >/dev/null || exit 1
! sudo ss -H -lnt | grep -Eq ":(25|465|587|2525)[[:space:]]" || exit 1
echo "SENDMAIL_BACKUP_LAB_PACKAGE_LAYOUT=accepted_if_trusted"
echo "SENDMAIL_BACKUP_LAB_SOURCE_CONFIG=unchanged"
echo "SENDMAIL_BACKUP_LAB_SNAPSHOT=verified_root_only"
echo "SENDMAIL_BACKUP_LAB_PRIMARY_SERVICE=stopped"
echo "SENDMAIL_BACKUP_LAB_EXTERNAL_DELIVERY_TESTED=no"

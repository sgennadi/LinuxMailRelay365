#!/usr/bin/env bash
# Real native Exim/Sendmail binary acceptance on a disposable Ubuntu 24.04 CI runner.
# No Microsoft tenant, SMTP recipient, queue submission, or daemon startup.
set -Eeuo pipefail

mta="$1"
case "$mta" in
  exim|sendmail) ;;
  *) echo "unsupported_mta" >&2; exit 2 ;;
esac

# Prevent package maintainer scripts from launching a mail daemon on CI.
policy=/usr/sbin/policy-rc.d
if test -e "$policy"; then
  echo "existing_policy_rc_d_refused" >&2
  exit 2
fi
printf '#!/bin/sh\nexit 101\n' | sudo tee "$policy" >/dev/null
sudo chmod 0755 "$policy"
trap 'sudo rm -f /usr/sbin/policy-rc.d' EXIT

# CI-only disposable Sendmail host: avoid unqualified-host DNS delays in
# native -bt -C parsing. Keep the production 15-second fail-closed timeout.
if test "$mta" = sendmail && test "${GITHUB_ACTIONS:-}" = true; then
  smoke_short=lmr365-sendmail-ci
  smoke_fqdn="${smoke_short}.example.invalid"
  printf '127.0.1.10 %s %s\n' "$smoke_fqdn" "$smoke_short" | sudo tee -a /etc/hosts >/dev/null
  sudo hostname "$smoke_short"
  if test "$(hostname -f)" != "$smoke_fqdn"; then
    echo 'sendmail_disposable_fqdn_resolution_failed' >&2
    exit 2
  fi
  echo 'NATIVE_SENDMAIL_CI_FQDN_READY=yes'
fi
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
if test "$mta" = exim; then
  sudo apt-get install -y -qq exim4-daemon-light
  ! systemctl is-active --quiet exim4.service
  ! systemctl is-active --quiet exim.service
  ! pgrep -x exim4
  ! pgrep -x exim
else
  sudo apt-get install -y -qq sendmail
  ! systemctl is-active --quiet sendmail.service
  ! pgrep -x sendmail
fi

# A test MTA package must not quietly turn on port 25, 465, 587 or 2525.
if sudo ss -H -lnt | grep -E ':(25|465|587|2525)[[:space:]]'; then
  echo "unexpected_smtp_listener_after_package_install" >&2
  exit 1
fi

# Record only path metadata, never config text, on the disposable runner.
if test "$mta" = sendmail; then
  sudo stat -c 'NATIVE_SENDMAIL_DIR_META=%n %F uid=%u mode=%a' /etc /etc/mail
  sudo stat -c 'NATIVE_SENDMAIL_CF_META=%n %F uid=%u mode=%a' /etc/mail/sendmail.cf /etc/mail/submit.cf
  sudo readlink -f /etc/mail
  sudo readlink -f /usr/sbin/sendmail
fi

# Root-only dry diagnostic: no backup, restore, SMTP send, service restart or queue mutation.
log="$(mktemp)"
trap 'rm -f "$log"; sudo rm -f /usr/sbin/policy-rc.d' EXIT
sudo python3 linux/restore-foreign-mta-config.py \
  --mta "$mta" --static-check > "$log"
grep -Fxq 'FOREIGN_STATIC_VERSION=1' "$log"
grep -Fxq "FOREIGN_STATIC_MTA=$mta" "$log"
grep -Fxq 'FOREIGN_STATIC_CHECK=passed_partial_parse_only' "$log"
grep -Fxq 'FOREIGN_STATIC_CONFIG_CHANGED=no' "$log"
grep -Fxq 'FOREIGN_STATIC_QUEUE_CHANGED=no' "$log"
grep -Fxq 'FOREIGN_STATIC_SERVICE_CHANGED=no' "$log"
grep -Fxq 'FOREIGN_STATIC_DELIVERY_VERIFIED=no' "$log"

# Fail closed for wrong MTA and invalid write approval on this read-only path.
other=sendmail
if test "$mta" = sendmail; then other=exim; fi
if sudo python3 linux/restore-foreign-mta-config.py \
    --mta "$other" --static-check > /dev/null 2>&1; then
  echo "wrong_mta_was_accepted" >&2
  exit 1
fi
if sudo python3 linux/restore-foreign-mta-config.py \
    --mta "$mta" --static-check --confirm RESTORE_STOPPED_FOREIGN_MTA_CONFIG \
    > /dev/null 2>&1; then
  echo "static_check_accepted_restore_confirmation" >&2
  exit 1
fi

# Validate the actual product aggregate protocol on the same stopped native
# package; no mail is submitted and the queue listing is never logged.
if test "${GITHUB_ACTIONS:-}" = true; then
  sudo python3 linux/inspect-mail-queue.py --scope "$mta" > "$log"
  grep -Fxq 'MAIL_QUEUE_VERSION=2' "$log"
  grep -Fxq "MAIL_QUEUE_SCOPE=$mta" "$log"
  grep -Fxq 'MAIL_QUEUE_CHANGES_APPLIED=no' "$log"
  grep -Fxq 'MAIL_QUEUE_ATOMIC=no' "$log"
  grep -Fxq 'MAIL_QUEUE_DELIVERY_VERIFIED=no' "$log"
  grep -Fxq 'MAIL_QUEUE_RESULT=ok' "$log"
  grep -Fxq 'MAIL_QUEUE_TOTAL=0' "$log"
  if test "$mta" = exim; then
    grep -Fxq 'MAIL_QUEUE_DETAIL_RESULT=ok' "$log"
    grep -Fxq 'MAIL_QUEUE_FROZEN=0' "$log"
    grep -Fxq 'MAIL_QUEUE_EXIM_OLDEST_MINUTES=0' "$log"
  else
    grep -Fxq 'MAIL_QUEUE_CLIENT_RESULT=ok' "$log"
    grep -Fxq 'MAIL_QUEUE_CLIENT_TOTAL=0' "$log"
    nonce="$(printf '%064d' 0)"
    for queue in mta msp; do
      sudo python3 linux/inspect-mail-queue.py --scope sendmail --sendmail-inventory "$queue" --selection-nonce "$nonce" > "$log"
      grep -Fxq "SENDMAIL_ITEMS_QUEUE=$queue" "$log"
      grep -Fxq 'SENDMAIL_ITEMS_RESULT=ok' "$log"
      grep -Fxq 'SENDMAIL_ITEMS_TOTAL=0' "$log"
      grep -Fxq 'SENDMAIL_ITEMS_LISTED=0' "$log"
      grep -Fxq 'SENDMAIL_ITEMS_CHANGES_APPLIED=no' "$log"
      grep -Fxq 'SENDMAIL_ITEMS_QUEUE_CLASS=normal' "$log"
    done
    echo "NATIVE_SENDMAIL_NORMAL_INVENTORIES=verified_independent_empty"
  fi
  echo "NATIVE_FOREIGN_MTA_QUEUE=verified_empty_sample_no_changes"
fi
! systemctl is-active --quiet sendmail.service
! systemctl is-active --quiet exim4.service
! systemctl is-active --quiet exim.service
echo "NATIVE_FOREIGN_MTA_STATIC_passed_disposable_systemd_no_mail_sent"

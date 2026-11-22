#!/usr/bin/env bash
# Read-only, non-login SSH probe. No per-user mail, spool messages, private
# crontabs, secrets or process arguments are read or printed.
set -u
export LC_ALL=C
printf 'MAIL_ORIGIN_VERSION=1\n'
if [ -x /usr/sbin/sendmail ] || command -v sendmail >/dev/null 2>&1; then
    printf 'MAIL_ORIGIN_SENDMAIL_CLI=present\n'
else
    printf 'MAIL_ORIGIN_SENDMAIL_CLI=not_observed\n'
fi
if command -v mail >/dev/null 2>&1 || command -v mailx >/dev/null 2>&1; then
    printf 'MAIL_ORIGIN_MAIL_CLI=present\n'
else
    printf 'MAIL_ORIGIN_MAIL_CLI=not_observed\n'
fi
if command -v postconf >/dev/null 2>&1; then
    # pickup/unix is the usual Postfix local-submission service. Existence
    # does not show that any user or scheduled job actually submitted mail.
    if postconf -M 2>/dev/null | grep -Eq '^[[:space:]]*pickup/unix([=[:space:]]|$)'; then
        printf 'MAIL_ORIGIN_PICKUP_CONFIG=configured\n'
    else
        printf 'MAIL_ORIGIN_PICKUP_CONFIG=not_observed\n'
    fi
else
    printf 'MAIL_ORIGIN_PICKUP_CONFIG=unverified\n'
fi
if command -v crond >/dev/null 2>&1 || command -v cron >/dev/null 2>&1 || \
   [ -e /usr/sbin/crond ] || [ -e /usr/sbin/cron ]; then
    printf 'MAIL_ORIGIN_SCHEDULER=present\n'
else
    printf 'MAIL_ORIGIN_SCHEDULER=not_observed\n'
fi
if command -v systemctl >/dev/null 2>&1; then
    printf 'MAIL_ORIGIN_SYSTEMD=available\n'
else
    printf 'MAIL_ORIGIN_SYSTEMD=unverified\n'
fi
printf 'MAIL_ORIGIN_CHANGES=no\n'

# SSH login profiles and the visible activity log (RC5)

The standard Linux connection checks and installer scripts are **non-login SSH
commands** (including `bash -s` or `sudo ... bash -s`). They do not ask Bash
to source `/etc/profile` or the user's `~/.bash_profile`, and no installer,
restore operation, firewall change or MTA discovery is switched to login mode.

Non-login check commands prepend standard system executable directories to
`PATH`, including `/usr/sbin` and `/usr/bin`, so `postconf`, `python3`
and other management tools can be found even when the SSH account has a
restricted interactive `PATH`. A successful SSH connection does not imply a
persistent shell; each command uses a new remote command session.

## Optional login-shell check

On the **SSH connection** page, choose **Inspect login profile and tool
availability**. This is not part of normal connection or installation. The
program first warns and requires explicit **Yes** because starting
`bash -lc` executes the SSH user's login startup scripts, which may perform
custom commands and have side effects. It does not use `sudo` and does not
change later command behavior.

The GUI reports only whether the login shell ran and whether selected tools
are available on its `PATH`: Python, OpenSSL, postconf, Exim/Exim4 and Sendmail.
It does **not** log the raw `PATH`, shell stdout/stderr, environment variables
or profile contents. A blocked, failed or incomplete probe remains unverified.

## Clearing the activity window

Expand **Show activity** in the fixed footer and choose **Clear log** at the
top of the activity pane. This action clears the visible TextBox only. It does
not reset connection or security state, delete stored reports, erase the
privacy-safe diagnostic journal, or disable subsequent activity logging.

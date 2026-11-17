#!/usr/bin/env bash
# LinuxMailRelay365 security & MTA capability inventory. READ-ONLY, no sudo.
# Printed values are status flags, not secrets or identifying token metadata.
set -uo pipefail
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ -r /etc/os-release ]; then . /etc/os-release; fi
val() { printf '%s=%s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }
val PROBE_VERSION 2
val OS_ID "${ID:-unknown}"
val OS_LIKE "${ID_LIKE:-}"
val OS_VERSION "${VERSION_ID:-unknown}"
val ARCH "$(uname -m)"
if has postconf; then
  val MTA postfix
  val POSTFIX_RELAY "$(postconf -h relayhost 2>/dev/null || true)"
  val POSTFIX_TRANSPORT "$(postconf -h default_transport 2>/dev/null || true)"
elif [ -e /etc/postfix ]; then
  val MTA unknown
elif [ -f /etc/mail/sendmail.cf ] || { has rpm && rpm -q sendmail >/dev/null 2>&1; }; then
  val MTA sendmail
elif has exim || has exim4; then
  val MTA exim
else
  val MTA none
fi
if has apt-get; then val PACKAGE_MANAGER apt
elif has dnf; then val PACKAGE_MANAGER dnf
elif has yum; then val PACKAGE_MANAGER yum
else val PACKAGE_MANAGER unsupported; fi
val PYTHON3 "$(has python3 && echo installed || echo missing)"
val OPENSSL "$(has openssl && echo installed || echo missing)"
# Device node: *presence* does not prove usable TPM, key protection, or ownership.
TPM_DEV=unavailable
if [ -c /dev/tpmrm0 ]; then TPM_DEV=/dev/tpmrm0
elif [ -c /dev/tpm0 ]; then TPM_DEV=/dev/tpm0; fi
val TPM_DEVICE "$TPM_DEV"
TPM_MAJOR=unknown
if [ -r /sys/class/tpm/tpm0/tpm_version_major ]; then
  TPM_MAJOR="$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null || echo unknown)"
fi
val TPM_VERSION "$TPM_MAJOR"
val TPM_DEVICE_ACCESS "$([ "$TPM_DEV" != unavailable ] && [ -r "$TPM_DEV" ] && [ -w "$TPM_DEV" ] && echo usable_by_ssh_user || echo not_verified)"
val TPM2_TOOLS "$(has tpm2_getcap && echo installed || echo missing)"
TPM_PROBE=not_tested
if [ "$TPM_DEV" != unavailable ] && [ "$TPM_MAJOR" = 2 ] && has tpm2_getcap && has timeout; then
  if timeout 6 tpm2_getcap properties-fixed >/dev/null 2>&1; then
    TPM_PROBE=responding
  else
    TPM_PROBE=unavailable_or_permission_denied
  fi
fi
val TPM2_COMMAND_PROBE "$TPM_PROBE"
val TPM2_PKCS11_TOOL "$(has tpm2_ptool && echo installed || echo missing)"
val PKCS11_TOOL "$(has pkcs11-tool && echo installed || echo missing)"
val PKCS11_MIDDLEWARE "$(has p11-kit && echo installed || echo missing)"
val PKCS11_TOKENS unknown
if has pkcs11-tool && has timeout; then
  if timeout 6 pkcs11-tool -L 2>/dev/null | grep -Eiq 'token label|token present'; then
    val PKCS11_TOKENS detected_unverified
  else
    val PKCS11_TOKENS none_or_inaccessible
  fi
fi
val OPENSSL_PKCS11_PROVIDER "$( [ -d /usr/lib64/ossl-modules ] || [ -d /usr/lib/x86_64-linux-gnu/ossl-modules ] || [ -d /usr/lib/ossl-modules ] && echo directory_present_unverified || echo unknown )"
# TPM2/HSM key integration is NOT automatically activated by discovery.
# The current XOAUTH2 transport uses an OpenSSL PEM key. A hardware key requires
# tested PKCS#11 or provider signing support AND a fresh Entra certificate upload.
val HARDWARE_SIGNING_CONFIGURED not_verified
val HARDWARE_SIGNING_AUTOMATICALLY_ENABLED no
val ENTRA_IP_POLICY not_checked_on_linux
val ENTRA_SIGNIN_MONITORING not_checked_on_linux
val SECURITY_CHANGES_APPLIED no
val SECURITY_NOTE 'TPM_HSM_detection_only_root_may_still_use_key'

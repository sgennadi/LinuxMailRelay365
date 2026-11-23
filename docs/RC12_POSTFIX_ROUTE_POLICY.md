# RC12 — read-only Postfix routing conflict review

**Unsigned RC12 test candidate; no production Apply and no verified mail delivery.**

RC12 extends the RC11 visual mail-rule planner. Once SSH discovery has
succeeded for the *current* Linux identity, the WinForms panel shows a
read-only conflict review based on effective Postfix declaration states.
It continues to treat every proposed routing card as a **hypothetical**
route, not an existing or installed rule.

## What is inspected

The Linux probe runs `postconf -h <setting>` and reports only one of
`declared`, `not_declared`, or `unverified` for each relevant setting:

- `transport_maps` and `relayhost`
- `sender_dependent_relayhost_maps`
- `sender_dependent_default_transport_maps`
- `smtp_sasl_password_maps`
- `smtp_sender_dependent_authentication`
- `smtp_sasl_auth_enable`
- `smtp_tls_policy_maps`
- existing local/virtual/relay domain and transport declarations

No map path, credentials, mailbox, sender address, map values or file
contents are returned. For the two Postfix boolean options, the effective
value `no` is correctly reported as `not_declared`, `yes` as
`declared`, and anything else as `unverified`.

The read-only observer warns when a proposed recipient domain appears
literally in `mydestination`; dynamic `$mydomain`-style entries are
explicitly unknown, not treated as safe. If the MTA is Exim, Sendmail,
none, or unknown, this Postfix-specific review refuses to validate routing.

## Why the checks are conservative

Postfix uses different address classes and routing mechanisms. For the
**default** recipient class, `transport_maps` overrides the delivery
transport and next hop; sender-dependent default transport can override
`default_transport`; sender-dependent relayhost is considered only
after those mechanisms. For **relay domains**, `relay_transport` is
also involved. Local and virtual mailbox classes require separate
preservation analysis.

This follows the official Postfix `postconf(5)` parameter documentation:
https://www.postfix.org/postconf.5.html

The presence of a map **never proves a particular lookup key matches**.
The GUI therefore does not simulate real Postfix precedence, inspect
remote credentials, promise TLS, or approve a delivery change.
The review's `CanApply` is unconditionally **false**.

### Explicitly not done

- No `postmap -q` or other live map-key queries
- No SMTP AUTH login, TCP test, message sending or cloud API writes
- No editing `main.cf`, `master.cf`, map files, SELinux or firewall
- No new SMTP port (including TCP 2525) created or suggested
- No secrets or map locations exported to Windows
- No automatic merge into RC11 or Stable

## Test gates

- Python tests verify active effective settings and ensure no secret
  map contents appear in the read-only report.
- C# self-tests cover overlap warnings, local-domain conflicts,
  unverified settings, unsupported MTAs, and unconditional Apply denial.
- Contract tests require GUI to remain read-only.
- Entire Linux and Windows x64/ARM64 CI must pass before this branch
  can be treated as an RC12 candidate.
- Physical 200%-DPI and real Linux/SMTP acceptance remain pending.

## Future change gates

1. Discover address classes correctly, including expanded/dynamic local
   domains and existing managed/unmanaged maps.
2. Prove route-key precedence with a dedicated safe read-only mechanism,
   not an invented one-table ordering.
3. Bind every candidate destination to DNS, TLS identity and provider
   sender rights, independently of inbound listener ports.
4. Preview exact managed-only changes, conflicts, SHA-bound backups,
   atomic writes, `postfix check`, reload/verify, and proven rollback.
5. Require a fresh explicit operator approval for **each** remote
   change, then conduct separate on-host and real-delivery acceptance.
6. Implement equivalent dedicated plans for Exim and Sendmail.

Nothing in RC12 constitutes authority to change running mail routes.

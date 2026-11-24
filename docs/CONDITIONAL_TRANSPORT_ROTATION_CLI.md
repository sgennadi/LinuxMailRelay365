# RC14 single-transport Credential Rotation CLI (development)

This experimental CLI uses the v2 recovery library and the existing owned
transport discovery and exclusive stopped-host maintenance guard. It does
not install anything on Linux when the source patch is applied. No automatic
Postfix stop/start/reload, queue writes, mail submissions, or provider AUTH
attempts are performed. Only an already owned password-authenticated sender
transport can be rotated. Existing RHEL/SELinux/ACL restrictions remain.

## Operations

All four operations use the existing maintenance confirmation
`I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES`, root access and the
shared maintenance lock. The administrator must independently prevent service
starts, mail submissions and concurrent configuration changes.

* `--review-rotation REVISION --index N`: non-secret review of one selected
  transport, existing file ownership, native policy and selected DNS/TLS
  endpoint. No credential request or AUTH.
* `--rotate REVISION --index N`: also requires `--approve-plan-sha256`,
  `--approve-review-sha256` and `--confirm ROTATE_ONE_STOPPED_POSTFIX_CREDENTIAL`.
  The input is a bounded JSON object on protected stdin containing exactly
  `username` and `password`. Never use shell arguments, a persistent request
  file or an audited stdin channel for passwords. Review and TLS are repeated
  before and after compilation; only the selected SASL map is changed. Both
  configs and other account maps remain untouched. The existing engine
  handles immediate rollback. Runtime SASL databases contain readable
  credentials, not encrypted secrets. No provider password validity is claimed.
* `--review-recovery REVISION`: inspect an interrupted rotation and identify
  a proven old retained, new retained or restored old map. No network or
  password input.
* `--recover REVISION`: requires exact plan and review approvals and
  `--confirm RECOVER_ONE_STOPPED_POSTFIX_CREDENTIAL`. Native verification of
  the retained map is mandatory. Reconciliation updates the private ownership
  record only, then removes the pending marker. It does not recreate a lost
  password or replace a retained map. Unknown scratch, foreign files or
  unrelated drift block recovery. Keep Postfix stopped if status is uncertain.

The public review token binds the revision, non-secret plan, selected index,
backend, account UID/GID, file identities, selected TLS evidence (rotation
only), and pending generation/state (recovery only). It is not an
authentication token and does not include credential DB hashes or native
configuration contents. Private installed-record validation and fresh policy
checks still run independently. Results are bounded fixed status receipts;
exceptions and native output are not included. Invalid CLI arguments are
reported generically without echoing argument values.

## Test boundaries

The local harness tests orchestrator contracts with simulated host/native
interfaces and real disposable config files. A combined harness exercises
actual v2 recovery snippets with the new orchestration and synthetic native
lookup responses. Neither proves repository integration, native hash/LMDB
rotation, real stopped-host acceptance, provider authentication, or delivery.
The Windows GUI is not integrated by this change. Do not deploy until the
actual source checkout, full repository CI, native Postfix and GUI have been
validated.

# Mail queue operations — post-RC18

This manager uses bounded native queue listings and explicit, short-lived
approval plans. Queue ordinals are sample-local, not reusable message IDs.
A command exit is not a delivery receipt. Refresh and inspect server logs
before taking further action. An uncertain result keeps the current GUI
window read-only, including after a successful inventory refresh.

| Operation | Postfix (primary or managed sidecar) | Exim (default queue) | Sendmail (MTA or MSP) |
| --- | --- | --- | --- |
| Inventory / refresh | Yes | Yes | Yes, normal and quarantine separately |
| Selected Retry / queue Flush | Experimental | Experimental | Experimental, normal class only |
| Hold / Freeze / Quarantine | Experimental | Experimental | Experimental, selected message |
| Release / Thaw | Experimental | Experimental | Experimental, selected message |
| Selected irreversible Delete | Held only, experimental | Frozen only, experimental | Not supported |

## Sendmail deletion boundary

The supported Sendmail command-line interface provides queue selection,
quarantine and unquarantine. No documented equivalent of Postfix
postsuper -d or Exim -Mrm was identified for this manager. A successful
quarantine transition preserves the message and is not a delete.

Sendmail maintains control files (qf or hf), data files (df), and possibly
additional queue artifacts. Directly deleting or renaming these files
on a running MTA can race with queue runners, submissions, and native
locking. No direct unlink, wildcard rm, bulk-delete, queue file editing
or automatic service stop is implemented. A future offline archival and
removal feature would require a separately designed maintenance transaction,
explicit operator approval, verified isolation from all queue writers,
recovery and real package/SELinux acceptance. It is not a release claim.

Reference: Sendmail Installation and Operation Guide 8.17.2, "Quarantined
Queue Items" and command-line options:
https://sendmail-doc.sendmaid.org/op_8.17.2.html

## Acceptance boundaries

- Ubuntu CI tests native Sendmail MTA/MSP queue previews, refusal of
  modified plans, confirmed quarantine/release, and real Retry/Flush
  against an isolated SMTP sink returning 451.
- The new EL matrix exercises actual RPM Sendmail packages on Rocky 8/9,
  AlmaLinux 9 and Oracle Linux 9. Each image is built before test execution;
  tests run in a disposable Docker overlay with no network and no mounted
  host queues. Image-mode RPMs are initialized with their own installed
  sysusers/tmpfiles definitions, without starting systemd or Sendmail.
  The EL client statistics file sm-client.st is accepted only when it is
  a verified package-owned regular file. Actual queue entries must be absent.
  Tests verify the package spool layout, synthetic submissions,
  independent class counts, refusal of changed plans, and quarantine/release.
  No successful Retry/Flush SMTP dispatch is attempted in that matrix.
- Container tests are not SELinux Enforcing or real systemd VM evidence.
  Those require a separately verified live VM. Real Microsoft 365 delivery
  and physical TPM acceptance also remain separate.

The new EL tests must pass before describing their results as verified.

## Shared visual semantics

All three message managers share the same color mapping. Blue indicates
native active/incoming/processing markers, amber indicates delay or a
warning, violet indicates hold/freeze/quarantine, slate indicates waiting,
and red indicates authentication/TLS/permanent/mixed delay categories or
an unknown operation outcome. Unmarked ordinary rows inherit Windows grid
colors. None of these colors proves that delivery succeeded.

Colors supplement existing text labels. The selected row always uses
Windows highlight colors; high contrast uses native system colors.
The Windows self-test checks state/diagnostic mapping and every custom
foreground/background pair for at least 4.5:1 contrast. This does not replace
visual checks at 100%/200% DPI, including Hebrew layout and high contrast.

## Compact queue windows and DPI acceptance

The three queue managers share a scrollable viewport and a DPI-scaled
minimum table height. Long translations, warning text and wrapped buttons
can increase content height without collapsing the grid. The user can
scroll to the controls. The pure sizing self-test covers 96, 144 and 192 DPI.
A separate CI capture exercises seven actual WinForms queue dialogs in
English, Russian and Hebrew, checking normal/compact geometry, scroll
reachability and action isolation. It saves 42 compact PNGs (table and
actions) and records actual runner DPI. All data are synthetic, remote
operations are disabled, and the screenshots do not establish physical
200% DPI acceptance. This new CI test must pass before claiming validation.

## Real Rocky KVM queue acceptance (pending CI)

The RC18 KVM recovery harness has an opt-in post-reboot queue test. It
requires the disposable Rocky 9.9 guest, a root-private boot-bound marker,
real KVM, systemd, SELinux Enforcing, stopped Sendmail units and a private
network/mount namespace. The native package queue paths are overlaid by
empty private on-disk directories with matching SELinux labels; unlike a
context-mounted tmpfs, these exercise ordinary file labeling. Native queue
previews, rejected approvals and confirmed MTA/MSP quarantine/release run
on synthetic messages. Native message labels are checked against policy.
After namespace exit the independent original RC18 recovery report must
match byte for byte. No original spool, MTA configuration or service is
modified by this queue fixture; its temporary disk is discarded with the VM.
This does not claim live external SMTP delivery or SELinux acceptance until
CI passes, nor does it prove real physical TPM or 200% hardware DPI.

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
  host queues. They verify the package spool layout, synthetic submissions,
  independent class counts, refusal of changed plans, and quarantine/release.
  No successful Retry/Flush SMTP dispatch is attempted in that matrix.
- Container tests are not SELinux Enforcing or real systemd VM evidence.
  Those require a separately verified live VM. Real Microsoft 365 delivery
  and physical TPM acceptance also remain separate.

The new EL tests must pass before describing their results as verified.

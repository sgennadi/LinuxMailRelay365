# LinuxMailRelay365 0.1.0 — release decision and acceptance record

**Decision: RC ONLY; signed production Stable 0.1.0 NOT AUTHORIZED.**

Branch: `release/v0.1.0-stable-candidate` (forked from last feature CI green
`9f8cabcdee05d34951c8f2de3d4e80cb582c508b`).
No merge to `main`, no Stable release/tag `v0.1.0`, no production deployment.

## Verified before candidate branch

- Full GitHub Actions CI on `9f8cabc`: [45012678280](https://github.com/sgennadi/LinuxMailRelay365/actions/runs/45012678280)
  and [45012674531](https://github.com/sgennadi/LinuxMailRelay365/actions/runs/45012674531), both successful.
- Experimental Rocky Linux 9.9 SELinux Enforcing KVM on same runtime code:
  [45012651545](https://github.com/sgennadi/LinuxMailRelay365/actions/runs/45012651545), successful.
  This was a disposable synthetic environment, not an authorized production host.
- CI Windows x64/ARM64 produces self-contained, **UNSIGNED** executable ZIPs with
  SHA-256 manifests. SHA-256 authenticates integrity of the selected bytes,
  not identity of a trusted code-signing publisher.

## Candidate publication (read-only production posture)

The CI branch-specific `release-candidate-publish` job may publish
`v0.1.0-rc.1` **only as an unsigned prerelease**, after every existing
Linux, RHEL-family and Windows test passes on the exact candidate SHA.
It verifies the archives contain one root-level EXE matching the manifest,
and refuses to overwrite an existing tag or release. The candidate binary
uses numeric product version `0.1.0` to exercise Stable-format code paths,
but is **not** a Stable production release. CI deliberately asserts that
`Test-LinuxMailRelay365SignedRelease.ps1` REFUSES the unsigned executables.

## Mandatory independent Stable gates (currently OPEN)

1. **Publisher provenance:** Obtain a Windows-trusted code-signing certificate
   and record the approved SHA-1/SHA-256 signer certificate thumbprint. Sign
   both x64 and ARM64 executables outside of CI; use the exact same publisher
   identity on both. Verify signature validity and matching thumbprint using
   `scripts/Test-LinuxMailRelay365SignedRelease.ps1`, producing its immutable
   signed-artifact manifest. No unsigned binaries or forged “signed” metadata.
2. **Authorized Microsoft 365 tenant:** Administrator-approved test tenant,
   exact Exchange Connector or XOAUTH2 permissions and verified source
   identity; validate internal **and external** recipient delivery,
   Exchange Message Trace and receiving inboxes. Direct Send is internal only.
3. **End-to-end Linux mailflow:** Test real client SMTP AUTH/STARTTLS and
   RFC5322 From protections where enabled; verify queue retry/restore,
   actual outbound route and negative unauthorized recipient/sender tests.
   Test a RHEL-family SELinux Enforcing *target* including reboot and any AVC
   checks; synthetic KVM alone is not production approval.
4. **Secret/hardware handling:** Validate real TPM/HSM key provenance,
   nonexportability and provider signing if hardware OAuth is enabled.
   Hardware OAuth must not silently fall back to exportable software keys.
5. **Recovery and abuse:** Dry-run controlled backup/restore, rollback,
   fail2ban/public SMTP abuse gating if public relay is enabled. Full live
   Sendmail tree restoration stays disabled until independently proven.
6. **Windows desktop QA:** On actual x64 and ARM64 hardware, inspect 100% and
   200% DPI, resize, RU/HE/EN, RTL, SSH, wizard flow and backups. Confirm
   a trusted SIGNED installed executable updates only to the same signer
   and fully rolls back on failure. A synthetic self-test alone is insufficient.

**Only after every relevant gate has recorded affirmative evidence:**
merge reviewed code to `main`, sign exact binaries, verify independent release
provenance and SHA-256, and publish `v0.1.0` as a non-prerelease. The existing
CI branch never publishes that tag and cannot forge the missing evidence.

## Why the requirement is not waived

An unsigned artifact called “Stable” would not pass the application's own
publisher-pinned auto-update path and could mislead a production operator
into deploying unvalidated Microsoft 365 sender configurations. Therefore
the candidate is explicitly marked **test only**.

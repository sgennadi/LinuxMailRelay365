# RC14 Credential Rotation GUI (development)

The cumulative v4 source patch includes the v2 interrupted-rotation recovery
library and v3 CLI. The separate GUI section is shown for a currently
inspected, stopped Postfix instance. It uses the exact manager-owned installed
transport inventory rather than the editable draft. Each password transport
has its own Review action. A successful reviewed receipt enables a separate
Rotate action only for that exact host, revision, plan and transport index.
Fresh exclusive maintenance and separate typed write confirmation are required.
The existing masked credential dialog is used for only the selected account.
No other passwords are read or requested; neither Postfix configuration file
nor the other maps are edited by rotation. Runtime SASL files contain readable
credentials and input auditing may record secrets, so an approved input
channel without secret recording is required. Clearing managed string
references does not guarantee secure erasure from process memory.

After an interrupted operation, use the existing recovery scan and select
or enter the revision, then Review interrupted rotation. The GUI verifies
exact fields and displays whether the old or new map is retained. Recovery
requires its own review and typed confirmation and no password input. The
backend must prove ownership and native lookup before changing its private
record; it cannot recreate missing old credentials. Keep Postfix stopped
until the result is understood and reinspection is complete.

All responses must have exact enumerated states, matching revision, plan,
index, backend and safety flags. A failed, stale or contradictory response
cannot be treated as successful. Discovery/scan or host change invalidates
rotation reviews. Every attempted rotation/recovery write invalidates other
discovery and routing evidence, even when the SSH result is uncertain.
No automatic service control, SMTP AUTH attempt or mail submission is added.
The existing no-AUTH and multi-provider installation/restore features remain.
English, Russian and Hebrew UI labels are included using existing controls.

## Acceptance boundary

The C# self-test is registered for the application's Windows test path.
Static Python tests cover source integration and contract invariants. They
are not a C# compiler or a WinForms runtime test. Verify Windows x64/ARM64
builds, 200% DPI/RTL, actual SSH/sudo input handling, native Hash/LMDB rotation
and recovery, and live mail delivery before production acceptance. Existing
SELinux/ACL and stopped-instance restrictions remain. No stable release is
claimed. Source integration targets a18ce398f8602cfa4d66ba558766927a81efe28e.

# Mail plan mini wizard (post-RC14)

The second main step now contains discovery, source, provider, recipients,
scenario, and review subpages. Next/back advance through one decision at a
time. Provider selection is explicit; current relay detection never
automatically chooses Microsoft 365. The review shows the current relay,
chosen source, provider, recipient scope and scenario with the existing
flow diagram. For Microsoft 365 the method and port remain undecided until
the next main step. A new inbound port is not preselected in the plan.

The delivery step contains the selected-plan summary, an edit-plan action,
provider-specific checks and the existing advanced routing/recovery tools.
Optional TPM/HSM and Entra security tools are on a separate subpage, accessible
from discovery and review. An explicit diagnostics-only skip remains available
if discovery is incomplete. Existing write and approval guards are unchanged.

The common page renderer guards recursive rebuilding, clamps scroll offsets
and resets to the top on subpage changes. Windows screenshot capture includes
actual viewport and reentrancy checks on every main page and the mini-page
missing-discovery states. Physical 200% DPI and real discovered-server
acceptance still require operator testing. The published RC14 is unchanged.

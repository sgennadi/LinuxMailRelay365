# Conditional Postfix map stage — RC14 development

Actual Linux-side staging of candidate map text files, not configuration Apply.
The CLI and Windows wizard share the same stage backend. It is a
narrow first backend for multiple disjoint proposed routes.

- Accepts 1–24 canonical lowercase rules in ASCII JSON (stdin).
- Initial stage supports STARTTLS/no AUTH only, exactly the selected outbound
  port. The text maps do not enforce TLS; an independent mandatory TLS policy
  and peer verification are still required. Implicit TLS, credentials,
  overlapping selectors and mixed sender/recipient rules are refused.
- The plan digest uses the existing Windows AdvancedRoutePlanner length-prefixed
  ASCII SHA-256 algorithm for this supported canonical subset.
- Plan requires no root and writes nothing. Stage requires root, the exact
  reviewed hash and typed STAGE_CONDITIONAL_MAPS_ONLY confirmation.
- Stage exclusively reserves /var/lib/linuxmailrelay365-conditional-stage/SHA.
  Parent and child directories are checked by no-follow descriptor traversal;
  private directories are 0700 and files 0600. The fixed manifest contains
  only hashes and an inactive marker. Manifest is written last; interrupted
  candidates cannot be verified, resumed or overwritten. Files are fsynced.
- Verify checks file identity, exact allowed file set, canonical plan,
  reconstructed content and manifest digests. No path or map content is returned.

Example JSON input (use a reviewed file containing this array):

    [{"selector":"exact-envelope-sender","pattern":"user@example.org","host":"relay.example.net","port":587,"tls":"starttls","auth":"none"}]

    python3 linux/stage-conditional-postfix-maps.py --plan < reviewed.json
    sudo python3 linux/stage-conditional-postfix-maps.py --stage --approve-sha256 REVIEWED_SHA --confirm STAGE_CONDITIONAL_MAPS_ONLY < reviewed.json
    sudo python3 linux/stage-conditional-postfix-maps.py --verify REVIEWED_SHA

No live map lookup, TLS/AUTH connection, service reload,
SMTP message, active Postfix config or firewall change is performed.
No production map ownership, safe rollback or delivery is proved by staging.
Privileged cleanup/retention is not implemented here.
Do not attach these files to live Postfix manually based on stage success.

Next: full routing precedence and target-host preservation checks,
tests, host/config identity binding, application-owned map manifest and safe
active backup/restore and rollback, then a separately approved narrow Apply.

Python tests operate on temporary directories only. CI discovery includes them.

## Native offline compilation and verification (RC14)

After the stage manifest is verified, use --compile PLAN_SHA --approve-manifest-sha256 STAGE_MANIFEST_SHA --confirm COMPILE_CONDITIONAL_MAPS_ONLY. This selects hash or lmdb from native postconf -m, uses a fresh private temporary config and generated source files, then verifies all rows using native postmap enumeration, positive lookup and one negative lookup. No lookup uses an existing host map. The compiled databases and a separate canonical manifest are stored exclusively in /var/lib/linuxmailrelay365-conditional-compiled/PLAN_SHA; no replacement is allowed. --verify-compiled PLAN_SHA validates both manifests and DB hashes, repeats native queries on private copies and rechecks the retained files. Neither operation starts or reloads Postfix, attaches a map, enables TLS/AUTH, opens a socket or sends mail. A raw dictionary match is NOT a proof of transport/recipient precedence. Real native hash/lmdb integration is exercised in Ubuntu Postfix CI; RHEL support still needs target-package and SELinux acceptance.

## Windows wizard

After discovery of an active Postfix, create supported rules and select Validate plan on Linux. Stage and Compile require separate typed confirmations; Verify actions can re-open an existing candidate for the exact validated plan. Receipts are bound locally to SSH identity, discovered config/inventory fingerprint and the plan SHA. A changed host or rule set invalidates the displayed receipt. Only fixed status and digests are logged. No activation operation exists.

Native command-only scratch config uses separate queue/data directories, an empty-service master.cf, and the package metadata directory /etc/postfix. The disposable CI fixture captures bounded native diagnostics on failures; production still suppresses output that may contain routing identifiers.

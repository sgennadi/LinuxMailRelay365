# RC14 systemd VM acceptance for the experimental offline CLI

Run only on a disposable official GitHub-hosted Ubuntu 24.04 systemd VM.
The workflow installs native Postfix, stops it, and prepares the narrowly
supported policy explicitly. The unmodified product CLI runs as root in a
dedicated network namespace. Its only peer is an isolated synthetic TLS SMTP
sink across veth on the 192.0.2.0/30 documentation subnet: no routes exist to
the ordinary guest network, real tenants or external mailboxes. No maintenance
or TLS evidence is injected into any application code.

The test checks the real preflight's refusal for a wrong name certificate signed
by the trusted fixture CA and for an occupied hold queue; confirms stale
approval and a restore with the native Postfix process active cannot change the
approved config; verifies Stage/Compile/Review/Apply and managed map ownership;
sends synthetic TLS mail on custom port 46517 and preserves local delivery; then
runs the actual offline Restore, confirms exact main.cf/master.cf bytes and map
removal, and checks that the same sender is routed via its previous port 46510.
Service starts/stops and synthetic test submissions are external fixture actions,
never manager actions. The recovery snapshot is retained until the ephemeral
VM is destroyed.

The lab does not imply Stable, GUI Apply, authenticated upstreams, SELinux,
remote mail or tenant acceptance. It changes neither main nor a release.

## CI integration

The `Postfix offline CLI VM acceptance` workflow is read-only for the
repository. Pull requests run the isolated systemd VM job when the offline
manager, preflight, transaction, stage, shared-Postfix writers, fixture or
workflow changes. For an independent rehearsal the same job also runs on
pushes to `test/postfix-rc14-pr-ci`. The runner does not retain checkout
credentials and no runner is provisioned for unrelated paths. Since this
is path-filtered, it should not be made a required check on unrelated PRs.

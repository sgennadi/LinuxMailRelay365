# Experimental offline conditional sender map manager

The CLI implements the first narrow actual configuration-write path, for
disjoint sender rules with STARTTLS/no AUTH only. It is not a Stable feature
and is not exposed by the Windows wizard. It never stops, starts, restarts,
or reloads a service. It never changes a listener, deletes queued mail,
configures credentials, or sends a message. Do not run on a production host
before real maintenance, package-specific acceptance and full system backup.

The administrator must explicitly arrange exclusive maintenance, stop the
primary Postfix instance, prevent all submissions/starts/config edits, and
verify the mail queues are empty. The script repeatedly samples these states;
this cannot enforce exclusivity against unrelated administrator actions.
The initial backend refuses SELinux and extended configuration metadata
rather than silently dropping labels or ACLs. It also requires the native
smtp, relay and trivial-rewrite services to be unchrooted; existing settings
are not rewritten to make the checks pass.

First obtain the plan and compiled manifest SHA-256 using the existing Stage
and Compile actions. On the same stopped host, with the same candidate:

    sudo python3 linux/manage-conditional-postfix-offline.py --review \
      --plan-sha256 PLAN --compiled-sha256 COMPILED \
      --maintenance-confirmation I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES

Review the exact transaction and evidence digests. The evidence binds native
config, DNS, TLS certificates, compiled manifest and the Postfix uid/gid.
The host checks are repeated after creating and verifying a root-only recovery
snapshot. Apply accepts only both exact reviewed digests and the explicit
maintenance and write confirmations:

    sudo python3 linux/manage-conditional-postfix-offline.py --apply \
      --plan-sha256 PLAN --compiled-sha256 COMPILED \
      --approve-transaction-sha256 TRANSACTION \
      --approve-evidence-sha256 EVIDENCE \
      --maintenance-confirmation I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES \
      --confirm APPLY_STOPPED_POSTFIX_SENDER_MAP

The only changes are a newly published root:postfix 0640 indexed map and
one appended sender_dependent_relayhost_maps parameter. No existing explicit
assignment or file can be overwritten. Post-write checks compare effective
configuration and native service definitions; all indexed keys and a missing
key are verified as the unprivileged Postfix user. A failed verification
attempts the exact snapshot rollback. A failed rollback leaves the retained
root-only recovery data and reports manual recovery required. Do not start
Postfix if the outcome is ambiguous.

Restore is a separate, explicit offline operation:

    sudo python3 linux/manage-conditional-postfix-offline.py \
      --restore BACKUP_SHA256 \
      --maintenance-confirmation I_HAVE_PREVENTED_CONCURRENT_MAIL_AND_CONFIG_CHANGES \
      --confirm RESTORE_STOPPED_POSTFIX_SENDER_MAP

Restore refuses any unrelated main.cf/master.cf drift or unknown map
contents; it never replaces a foreign map. The recovery directory is retained
and may contain sensitive original configuration. It is not exported to the
GUI. The operator, not the application, controls any later service start.

Unit tests exercise the real transaction library using temporary files and
mocked native/preflight interfaces. The Ubuntu native smoke additionally
compiles real indexed maps, invokes the actual transaction orchestration with
an isolated Postfix configuration, checks effective settings with native
postconf, queries the new map as the Postfix account, and verifies explicit
restore and injected post-write failure rollback. It checks that the primary
main.cf/master.cf identity and bytes remain unchanged. Only the fixture's
maintenance and remote TLS evidence are injected; this is NOT end-to-end
acceptance of the real host maintenance CLI, address-class routing or delivery.
SELinux labels/ACLs, GUI integration, provider authorization and real mail
delivery remain separate gates. Test execution must pass in CI.

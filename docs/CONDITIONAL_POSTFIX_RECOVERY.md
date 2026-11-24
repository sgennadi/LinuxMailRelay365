# Conditional recovery inventory (RC14)

Read-only companion to the experimental offline sender-map manager. It does
not stop or start Postfix, create a lock or recovery directory, alter queues,
remove maps, display configuration contents or authorize Restore.

    sudo python3 linux/inspect-conditional-postfix-recovery.py --list
    sudo python3 linux/inspect-conditional-postfix-recovery.py --inspect BACKUP_SHA256

Each entry contains only a recovery SHA-256 and an enumerated observation.
The root-only inventory is bounded to 64 named recovery records; incomplete
records are visible and unknown directory names refuse the list.

* original_no_map: original configuration is present and candidate DB absent.
  This can be a backup-only attempt or completed Restore.
* original_owned_map: original config and a verified owned DB remain; possible
  interrupted transaction.
* configured_owned_map: proposed config and verified published DB are present.
  This is not evidence of a running service or successful mail delivery.
* configured_map_missing: proposed config refers to an absent DB.
* map_ownership_unproven / map_identity_or_content_changed: do not delete the
  map on the strength of matching bytes.
* config_drift / unexpected_source_file / different_config_directory:
  existing recovery information cannot authorize overwriting the current state.
* invalid_or_missing_backup / state_unverified / unstable_observation:
  inspect the host and retained recovery data before proceeding.

Two observations and a reread of the backup reduce inconsistent reports but
are not an exclusive maintenance lock. An external process may change the
state immediately afterward. Actual Restore still needs its separate typed
approval, stopped-host guard, exact backup integrity and ownership checks.
Only temporary-directory unit tests are added here; GUI integration and
native full-maintenance acceptance are separate work.

The WinForms recovery panel embeds the same read-only inventory backend. Scan requires current Postfix discovery, validates the returned bounded list and invalidates displayed observations when the SSH/discovery context changes. Only backup digests and enumerated states are shown, not original configuration. No write action is included in this panel.

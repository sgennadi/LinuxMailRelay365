"""Native seven-stage primary broker installer acceptance, disposable VM only.

Called after the existing native TPM fixture has provisioned a synthetic
primary identity. No production host, external SMTP, Entra or physical TPM.
A failure leaves the transaction's fixed phase diagnostic for CI and the
outer KVM runner discards the entire guest. No guessed partial rollback.
"""
import grp
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def run_fixture(F, T, P, config, queue, baseline, snapshot, stopped):
    F.disposable()
    F.need(os.environ.get("LMR365_KVM_TPM_BROKER_INSTALL_ACCEPTANCE") == "true" and
           os.environ.get("LMR365_KVM_TPM_BROKER_ACCEPTANCE") != "true" and
           'VERSION_ID="10.3"' in Path("/etc/os-release").read_text().splitlines(),
           "broker_install_disposable_rocky10_only")
    # The host stages exactly the reviewed package in root-owned 0755/0644
    # directories. -I excludes untrusted PYTHONPATH; add only this directory.
    for directory in (HERE,) + tuple(HERE.parents):
        meta = directory.lstat()
        F.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and
               not meta.st_mode & 0o6022, "broker_install_fixture_package_unsafe")
    sys.path.insert(0, str(HERE))
    import m365_tpm_broker_coordinator as C
    import m365_tpm_broker_activation as A
    import m365_tpm_broker_device as D
    import m365_tpm_broker_policy as S

    inspector = C.load_preview()
    def exclusive(stage, direction):
        F.disposable()
        F.need(os.environ.get("LMR365_KVM_TPM_BROKER_INSTALL_ACCEPTANCE") == "true",
               "broker_install_fixture_gate")
        stopped(queue)
        F.need(snapshot(config) == baseline, "broker_install_postfix_config_changed")
        # Only this dedicated swtpm-backed disposable guest is reserved
        # for the test, with no customer accounts or other TPM workloads.
        F.need(Path("/sys/fs/selinux/enforce").read_bytes().strip() == b"1",
               "broker_install_enforcing_lost")

    exclusive(None, None)
    inventory = S.inventory()
    before_device = D.observe_native()
    before_identity = C.identity.read_primary_snapshot()
    handles = T.read_capabilities()
    F.need(handles == {"0x81010001", "0x81010002"},
           "broker_install_fixture_handles")
    mail = pwd.getpwnam("m365mailer")
    gid = grp.getgrnam("m365mailer").gr_gid
    F.need(before_device.gid == gid and before_device.mode == 0o660,
           "broker_install_fixture_device_baseline")
    # Pick explicit free system IDs; the native account adapter independently
    # validates local/NSS reservations, login.defs and process ownership.
    occupied_uids = {item.pw_uid for item in pwd.getpwall()}
    occupied_gids = {item.gr_gid for item in grp.getgrall()} | {
        item.pw_gid for item in pwd.getpwall()}
    selected = next((n for n in range(850, 950)
                     if n not in occupied_uids and n not in occupied_gids), None)
    F.need(selected is not None and selected != mail.pw_uid and selected != gid,
           "broker_install_fixture_system_id_unavailable")
    with tempfile.TemporaryDirectory(prefix="lmr365-install-acceptance-", dir="/run") as folder:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            journal = C.tx.Journal(fd)
            with journal.exclusive():
                try:
                    print("LMR365_BROKER_INSTALL_STAGE=review", flush=True)
                    approved = C.prepare_review(journal, selected, selected,
                                                exclusive, inspector)
                    review, pp = C.read_review(journal)
                    F.need(C.tx.sha(approved), "broker_install_approval_unverified")
                    print("LMR365_BROKER_INSTALL_REVIEW=verified", flush=True)
                    with C.native_coordinator(review, pp, exclusive, inspector) as coordinator:
                        print("LMR365_BROKER_INSTALL_STAGE=apply", flush=True)
                        installed = coordinator.apply(journal, approved, C.tx.APPLY)
                        F.need(installed["phase"] == "installed" and
                               installed["completed"] == len(C.tx.STAGES) and
                               installed["pending"] is None,
                               "broker_install_not_complete")
                        for item in coordinator.plan()["stages"]:
                            F.need(coordinator.probe(item["name"]) == item["after"],
                                   "broker_install_stage_unverified")
                        print("LMR365_BROKER_INSTALL_APPLY=all_seven_native_stages", flush=True)
                        # READY is emitted only after the real TPM2 signature
                        # and independent certificate verification. Verify a
                        # new systemd invocation, not the old journal receipt.
                        status = A.show(A.command, A.KEYS)
                        F.need(coordinator.activation.state(), "broker_install_not_ready")
                        print("LMR365_BROKER_INSTALL_PS256=verified_startup", flush=True)
                        exclusive("activation", "restart")
                        A.command(A.SYSTEMCTL, ["restart", A.UNIT])
                        coordinator.activation.wait_ready()
                        restarted = A.show(A.command, A.KEYS)
                        F.need(restarted["InvocationID"] != status["InvocationID"] and
                               coordinator.activation.state(),
                               "broker_install_restart_unverified")
                        print("LMR365_BROKER_INSTALL_RESTART=new_verified_invocation", flush=True)
                        print("LMR365_BROKER_INSTALL_STAGE=rollback", flush=True)
                        rolled = coordinator.rollback(journal, approved, C.tx.ROLLBACK)
                        F.need(rolled["phase"] == "rolled_back" and rolled["completed"] == 0 and
                               rolled["pending"] is None, "broker_install_rollback_unverified")
                        for item in coordinator.plan()["stages"]:
                            F.need(coordinator.probe(item["name"]) == item["before"],
                                   "broker_install_rollback_stage_unverified")
                        print("LMR365_BROKER_INSTALL_ROLLBACK=all_seven_native_stages", flush=True)
                    exclusive(None, None)
                    F.need(inspector.absent_install() and S.inventory() == inventory and
                           D.observe_native() == before_device and
                           before_identity.matches(C.identity.read_primary_snapshot()) and
                           T.read_capabilities() == handles,
                           "broker_install_native_baseline_not_restored")
                    print("LMR365_BROKER_INSTALL_BASELINE=restored", flush=True)
                    print("LMR365_BROKER_INSTALL_CLOUD_TESTED=no", flush=True)
                    print("LMR365_BROKER_INSTALL_REBOOT_TESTED=no", flush=True)
                    print("LMR365_BROKER_INSTALL_PHYSICAL_TPM_TESTED=no", flush=True)
                except Exception:
                    # Fixed phase/stage identifiers only. Never print
                    # assertion, policy content, queue data or secrets.
                    state = journal.read()
                    if state is not None:
                        pending = state["pending"]
                        print("LMR365_BROKER_INSTALL_FAILURE_PHASE=" + state["phase"], flush=True)
                        print("LMR365_BROKER_INSTALL_FAILURE_PENDING=" +
                              (pending["name"] if pending else "none"), flush=True)
                        print("LMR365_BROKER_INSTALL_FAILURE_COMPLETED=" +
                              str(state["completed"]), flush=True)
                    raise
        finally:
            os.close(fd)

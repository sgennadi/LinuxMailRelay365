"""Test the installer's shell helper without root, packages or actual relabels."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=(ROOT/"linux/install-postfix-m365-xoauth2.sh").read_text()
HELPERS=SCRIPT.split("# BEGIN PRIMARY_INSTALLER_SELINUX_HELPERS\n",1)[1].split(
    "# END PRIMARY_INSTALLER_SELINUX_HELPERS",1)[0]

class PrimaryInstallerSelinuxTests(unittest.TestCase):
    def shell(self, body, mode="Enforcing", restore_rc=0, actual=None):
        context="system_u:object_r:postfix_etc_t:s0"
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/"app.key").touch()
            (p/"signer.py").touch()
            (p/"symlink").symlink_to(p/"app.key")
            env=dict(os.environ, MODE=mode, SETUP_MODE=mode,
                     RESTORE_RC=str(restore_rc), EXPECTED=context,
                     ACTUAL=context if actual is None else actual, FIXTURE=tmp)
            mocks=r'''
read_installer_selinux_mode() { printf '%s\n' "$MODE"; }
restorecon() { printf 'RELABEL:%s\n' "$2"; return "$RESTORE_RC"; }
matchpathcon() { printf '%s\n' "$EXPECTED"; }
stat() { printf '%s\n' "$ACTUAL"; }
SELINUX_SETUP_MODE="$SETUP_MODE"
'''
            return subprocess.run(["bash","-c","set -Eeuo pipefail\n"+HELPERS+mocks+body],
                    env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    universal_newlines=True,timeout=10)

    def test_relabel_failure_is_fatal(self):
        r=self.shell('check_installer_selinux_paths label "$FIXTURE/app.key"\necho READY\n',restore_rc=1)
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn("READY",r.stdout)
        self.assertIn("restorecon failed",r.stderr)

    def test_explicit_paths_and_verify_without_relabel(self):
        r=self.shell('check_installer_selinux_paths label "$FIXTURE/app.key" "$FIXTURE/signer.py"\n'
                     'check_installer_selinux_paths verify "$FIXTURE/app.key" "$FIXTURE/signer.py"\n')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(len(r.stdout.splitlines()),2)
        self.assertTrue(all(line.startswith("RELABEL:") for line in r.stdout.splitlines()))
        self.assertTrue(r.stdout.splitlines()[1].endswith("/signer.py"))

    def test_wrong_full_context_or_symlink_refused(self):
        r=self.shell('check_installer_selinux_paths label "$FIXTURE/app.key"\n',
                     actual="unconfined_u:object_r:postfix_etc_t:s0")
        self.assertNotEqual(r.returncode,0)
        self.assertIn("context mismatch",r.stderr)
        r=self.shell('check_installer_selinux_paths label "$FIXTURE/symlink"\n')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn("RELABEL",r.stdout)

    def test_disabled_and_mode_drift(self):
        for mode in ("Disabled","inactive_or_unavailable"):
            r=self.shell('check_installer_selinux_paths label "$FIXTURE/app.key"\n',mode,restore_rc=1)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(r.stdout,"")
        r=self.shell('MODE=Permissive\ncheck_installer_selinux_paths label "$FIXTURE/app.key"\n')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn("RELABEL",r.stdout)

    def test_check_order_and_scope(self):
        start=SCRIPT.index("check_installer_selinux_paths label \"$CONF_DIR\"")
        prepare=SCRIPT.index("Certificate preparation complete")
        self.assertLess(start,prepare)
        runtime=SCRIPT.index('check_installer_selinux_paths label "$CONF_DIR/app.json"')
        self.assertLess(runtime,SCRIPT.index("postconf -e 'smtpd_client_restrictions"))
        verify=SCRIPT.index('check_installer_selinux_paths verify "$CONF_DIR"')
        self.assertLess(verify,SCRIPT.index("systemctl enable --now postfix"))
        self.assertIn("/usr/local/libexec/m365_hardware_signer.py",SCRIPT[runtime:runtime+220])
        self.assertIn("SELINUX_PIPE_DOMAIN=not_verified",SCRIPT)
        self.assertNotIn("restorecon -R",SCRIPT)
        self.assertNotIn("setenforce 0",SCRIPT)


class WorkflowShellSyntaxTests(unittest.TestCase):
    def test_all_workflow_shell_syntax_checks_validate_one_script_at_a_time(self):
        # A multi-file bash -n command silently ignores invalid later files.
        import re
        for path in (".github/workflows/ci.yml", ".github/workflows/rocky-enforcing-vm.yml"):
            source=(ROOT/path).read_text()
            for line in source.splitlines():
                if re.match(r"^\s*bash -n ",line):
                    args=line.strip().split()
                    self.assertTrue(len(args)==3 or args==["bash","-n",'"$script"',"||","exit","1"],
                                    path+": "+line)
            self.assertIn('bash -n "$script" || exit 1',source)

    def test_shell_syntax_loop_rejects_invalid_second_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            good=Path(tmp)/"good.sh"
            bad=Path(tmp)/"bad.sh"
            good.write_text("echo OK\n")
            bad.write_text("fi\n")
            command='for script in "$@"; do bash -n "$script" || exit 1; done'
            result=subprocess.run(["bash","-c",command,"syntax-check",str(good),str(bad)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertNotEqual(result.returncode,0)
            bad.write_text("echo OK\n")
            result=subprocess.run(["bash","-c",command,"syntax-check",str(good),str(bad)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)


class PrimaryVmReceiptTests(unittest.TestCase):
    def test_every_required_marker_is_checked_by_actual_bash(self):
        source=(ROOT/"tests/rocky_vm_boot_enforcing.sh").read_text()
        self.assertEqual(source.count("LMR365_GUEST_EXTERNAL_MAIL_DELIVERY_TESTED=no"),1)
        self.assertTrue(source.rstrip().endswith('echo "LMR365_GUEST_EXTERNAL_MAIL_DELIVERY_TESTED=no"'))
        syntax=subprocess.run(["bash","-n"],input=source.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(syntax.returncode,0,syntax.stderr)
        block=source.split("# BEGIN PRIMARY_VM_RECEIPT_CHECK\n",1)[1].split(
            "# END PRIMARY_VM_RECEIPT_CHECK",1)[0]
        required=["LMR365_PRIMARY_VM_FIXTURE_POLICY=exact_context_baseline","LMR365_PRIMARY_VM_REVIEW=native_policy_and_postconf","LMR365_PRIMARY_VM_APPLY=verified_native_labels","LMR365_PRIMARY_VM_BACKUP=verified_native_private_labels","LMR365_PRIMARY_VM_RESTORE=exact_bytes_metadata_and_native","LMR365_PRIMARY_VM_ENFORCING_REVIEW=native_runtime_synthetic_auth","LMR365_PRIMARY_VM_PIPE_DOMAIN=postfix_pipe_t","LMR365_PRIMARY_VM_PIPE_PS256=verified_fixture_certificate","LMR365_PRIMARY_VM_PIPE_QUEUE=correlated_and_empty","LMR365_PRIMARY_VM_PIPE_TCP443=loopback_verified","LMR365_PRIMARY_VM_PIPE_TCP587=loopback_verified", "LMR365_PRIMARY_VM_PIPE_BASELINE=restored_exact_bytes", "LMR365_PRIMARY_VM_BASELINE=running_restored","LMR365_PRIMARY_VM_REAL_OAUTH_AUTH=no","LMR365_PRIMARY_VM_REAL_PIPE_DELIVERY=no"]
        mismatch="LMR365_PRIMARY_VM_LABEL_MISMATCH=refused_without_write"
        with tempfile.TemporaryDirectory() as tmp:
            receipt=Path(tmp)/"primary-mailbox"
            def run(rows):
                receipt.write_text("\n".join(rows)+"\n")
                return subprocess.run(["bash","-c","set -Eeuo pipefail\nwork=\"$1\"\n"+block,
                    "receipt-check",tmp],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            rows=[mismatch]+required
            good=run(rows)
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertEqual(run(["LMR365_PRIMARY_VM_LABEL_MISMATCH=not_present"]+required).returncode,0)
            for i in range(len(rows)):
                with self.subTest(missing=rows[i]):
                    self.assertNotEqual(run(rows[:i]+rows[i+1:]).returncode,0)
            self.assertNotEqual(run([mismatch]+required[:-1]+["prefix "+required[-1]]).returncode,0)

if __name__=="__main__":
    unittest.main()

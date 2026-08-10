import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from hardaudit import (
    Finding,
    audit_users,
    classify_deleted_executable,
    classify_update_severity,
    print_finding,
    get_effective_sshd_settings,
    scan_deleted_executables,
    shadow_permissions_unsafe,
)


class DeletedExecutableTests(unittest.TestCase):
    def test_detects_deleted_executable_and_ignores_normal_one(self):
        with tempfile.TemporaryDirectory() as proc:
            suspicious = os.path.join(proc, "4242")
            normal = os.path.join(proc, "4243")
            os.makedirs(suspicious)
            os.makedirs(normal)

            os.symlink("/tmp/.cache-agent (deleted)", os.path.join(suspicious, "exe"))
            with open(os.path.join(suspicious, "comm"), "w", encoding="utf-8") as f:
                f.write("cache-agent\n")

            os.symlink("/usr/bin/python3", os.path.join(normal, "exe"))
            with open(os.path.join(normal, "comm"), "w", encoding="utf-8") as f:
                f.write("python3\n")

            self.assertEqual(
                scan_deleted_executables(proc),
                [{
                    "pid": 4242,
                    "name": "cache-agent",
                    "target": "/tmp/.cache-agent (deleted)",
                }],
            )

    def test_missing_proc_directory_returns_empty_list(self):
        self.assertEqual(scan_deleted_executables("/path/that/does/not/exist"), [])

    def test_system_binary_replaced_by_update_is_low_risk(self):
        self.assertEqual(classify_deleted_executable("/usr/lib/systemd/systemd-logind (deleted)"), "LOW")

    def test_deleted_binary_in_temporary_directory_is_high_risk(self):
        self.assertEqual(classify_deleted_executable("/tmp/.cache-agent (deleted)"), "HIGH")


class FalsePositiveRegressionTests(unittest.TestCase):
    def test_shadow_0640_owned_by_root_shadow_is_accepted(self):
        self.assertFalse(shadow_permissions_unsafe(0o640, 0, "shadow"))

    def test_shadow_world_readable_is_rejected(self):
        self.assertTrue(shadow_permissions_unsafe(0o644, 0, "shadow"))

    def test_shadow_group_writable_is_rejected(self):
        self.assertTrue(shadow_permissions_unsafe(0o660, 0, "shadow"))

    def test_many_regular_updates_are_not_called_critical(self):
        self.assertEqual(classify_update_severity(77, 0), "HIGH")

    def test_many_security_updates_are_critical(self):
        self.assertEqual(classify_update_severity(77, 25), "CRITICAL")

    @patch("hardaudit.os.geteuid", return_value=0)
    @patch("hardaudit.subprocess.run")
    @patch("hardaudit.pwd.getpwall", return_value=[])
    def test_root_shell_alone_is_not_reported_as_root_login(self, _getpwall, run, _geteuid):
        run.return_value.stdout = ""
        module = audit_users()
        self.assertNotIn("Root login actif", [finding.title for finding in module.findings])

    def test_finding_prints_a_manual_verification_command(self):
        finding = Finding("Exemple", "Fait observe.", "MEDIUM", verify="stat -c '%a %U %G' /etc/shadow")
        output = StringIO()
        with redirect_stdout(output):
            print_finding(finding, 0)
        self.assertIn("Verifier : stat -c", output.getvalue())

    @patch("hardaudit.subprocess.run")
    def test_ssh_audit_uses_effective_configuration(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "permitrootlogin prohibit-password\npasswordauthentication no\nport 2222\n"
        settings = get_effective_sshd_settings("/etc/ssh/sshd_config")
        self.assertEqual(settings["permitrootlogin"], "prohibit-password")
        self.assertEqual(settings["passwordauthentication"], "no")
        self.assertEqual(settings["port"], "2222")


if __name__ == "__main__":
    unittest.main()

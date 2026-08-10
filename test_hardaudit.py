import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from hardaudit import (
    Finding,
    audit_kernel,
    audit_network,
    audit_users,
    classify_deleted_executable,
    classify_update_severity,
    extract_unreviewed_wildcard_ports,
    firewall_has_default_deny,
    print_finding,
    get_effective_sshd_settings,
    kernel_sysctl_is_unsafe,
    scan_deleted_executables,
    scan_fs_link_protections,
    scan_unrestricted_io_uring,
    scan_unprivileged_bpf,
    scan_unprivileged_tty_ldisc_autoload,
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


class FilesystemProtectionTests(unittest.TestCase):
    def _write_sysctls(self, root, values):
        for name, value in values.items():
            with open(os.path.join(root, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_disabled_protections_are_reported_but_stronger_value_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_sysctls(root, {
                "protected_hardlinks": 0,
                "protected_symlinks": 1,
                "protected_fifos": 0,
                "protected_regular": 2,
            })
            findings = scan_fs_link_protections(root)
            self.assertEqual(
                [finding[0] for finding in findings],
                ["Hardlinks non proteges", "FIFO non proteges"],
            )

    def test_representative_hardened_linux_values_pass(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_sysctls(root, {
                "protected_hardlinks": 1,
                "protected_symlinks": 1,
                "protected_fifos": 1,
                "protected_regular": 2,
            })
            self.assertEqual(scan_fs_link_protections(root), [])


class UnprivilegedBpfTests(unittest.TestCase):
    def test_enabled_unprivileged_bpf_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_unprivileged_bpf(sysctl.name), 0)

        with patch("hardaudit.scan_unprivileged_bpf", return_value=0):
            findings = [f for f in audit_kernel().findings if "BPF" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_representative_ubuntu_default_disables_unprivileged_bpf(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("2\n")
            sysctl.flush()
            self.assertIsNone(scan_unprivileged_bpf(sysctl.name))


class IoUringRestrictionTests(unittest.TestCase):
    def test_unrestricted_io_uring_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_unrestricted_io_uring(sysctl.name), 0)

        with patch("hardaudit.scan_unrestricted_io_uring", return_value=0):
            findings = [f for f in audit_kernel().findings if "io_uring" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_restricted_modes_pass(self):
        for value in ("1\n", "2\n"):
            with self.subTest(value=value.strip()):
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
                    sysctl.write(value)
                    sysctl.flush()
                    self.assertIsNone(scan_unrestricted_io_uring(sysctl.name))


class TtyLdiscAutoloadTests(unittest.TestCase):
    def test_unprivileged_tty_ldisc_autoload_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertEqual(scan_unprivileged_tty_ldisc_autoload(sysctl.name), 1)

        with patch("hardaudit.scan_unprivileged_tty_ldisc_autoload", return_value=1):
            findings = [f for f in audit_kernel().findings if "Autoload TTY" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_hardened_value_blocks_unprivileged_autoload(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertIsNone(scan_unprivileged_tty_ldisc_autoload(sysctl.name))


class KernelSysctlSemanticsTests(unittest.TestCase):
    def test_kptr_restrict_stronger_mode_is_accepted(self):
        self.assertFalse(kernel_sysctl_is_unsafe("kernel.kptr_restrict", "2"))

    def test_kptr_restrict_disabled_mode_is_rejected(self):
        self.assertTrue(kernel_sysctl_is_unsafe("kernel.kptr_restrict", "0"))

    def test_stricter_ptrace_scope_is_accepted(self):
        self.assertFalse(kernel_sysctl_is_unsafe("kernel.yama.ptrace_scope", "3"))

    def test_permissive_perf_access_is_rejected(self):
        self.assertTrue(kernel_sysctl_is_unsafe("kernel.perf_event_paranoid", "1"))

    def test_representative_ubuntu_perf_lockdown_is_accepted(self):
        self.assertFalse(kernel_sysctl_is_unsafe("kernel.perf_event_paranoid", "4"))

    def test_perf_finding_is_emitted_for_weak_value(self):
        real_open = open

        def fake_open(path, *args, **kwargs):
            if path == "/proc/sys/kernel/perf_event_paranoid":
                return StringIO("1\n")
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=fake_open):
            findings = [f for f in audit_kernel().findings if "Perf expose" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_exact_boolean_control_stays_exact(self):
        self.assertTrue(kernel_sysctl_is_unsafe("kernel.dmesg_restrict", "0"))
        self.assertFalse(kernel_sysctl_is_unsafe("kernel.dmesg_restrict", "1"))


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

    def test_ufw_default_deny_overrides_iptables_accept(self):
        self.assertTrue(firewall_has_default_deny(
            "Chain INPUT (policy ACCEPT)", "", "Status: active\nDefault: deny (incoming), allow (outgoing)"
        ))

    def test_nft_input_policy_drop_is_detected(self):
        nft = "chain input { type filter hook input priority filter; policy drop; }"
        self.assertTrue(firewall_has_default_deny("", nft, "Status: inactive"))

    def test_accept_only_firewall_is_not_default_deny(self):
        self.assertFalse(firewall_has_default_deny(
            "Chain INPUT (policy ACCEPT)", "chain input { policy accept; }", "Status: inactive"
        ))

    def test_wildcard_ports_are_grouped_and_known_public_ports_ignored(self):
        output = "\n".join([
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
            "LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*",
            "LISTEN 0 128 *:10050 *:*",
        ])
        self.assertEqual(extract_unreviewed_wildcard_ports(output), ["3306", "10050"])

    def test_info_finding_has_no_score_penalty(self):
        self.assertEqual(Finding("Contexte", "Attendu", "INFO").penalty, 0)

    @patch("hardaudit._capture")
    def test_allowed_port_stays_visible_without_penalty(self, capture):
        capture.return_value = (0, "LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*\nLISTEN 0 128 *:10050 *:*")
        module = audit_network(allowed_ports={"3306"})
        self.assertEqual(module.score, 9)
        self.assertEqual(
            [(finding.severity, finding.title) for finding in module.findings],
            [
                ("MEDIUM", "1 port(s) en ecoute sur toutes les interfaces"),
                ("INFO", "1 port(s) attendu(s) selon le contexte fourni"),
            ],
        )


if __name__ == "__main__":
    unittest.main()

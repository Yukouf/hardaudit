import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import hardaudit
from hardaudit import (
    Finding,
    audit_kernel,
    audit_network,
    audit_filesystem,
    audit_users,
    classify_deleted_executable,
    classify_update_severity,
    extract_unreviewed_wildcard_ports,
    firewall_has_default_deny,
    print_finding,
    get_effective_sshd_settings,
    kernel_sysctl_is_unsafe,
    scan_kernel_lockdown_disabled,
    scan_kexec_enabled,
    scan_executable_memfd_default,
    scan_deleted_executables,
    scan_fs_link_protections,
    scan_mount_options,
    scan_proc_hidepid,
    scan_unsafe_ipv4_redirect_senders,
    scan_unsafe_ipv4_redirects,
    scan_unprotected_reverse_paths,
    scan_unsafe_suid_dumps,
    scan_unrestricted_io_uring,
    scan_unmediated_unprivileged_io_uring,
    scan_unprivileged_bpf,
    scan_legacy_tiocsti_enabled,
    scan_unprivileged_tty_ldisc_autoload,
    scan_unprivileged_userfaultfd,
    scan_unrestricted_unprivileged_userns,
    scan_zero_page_mappable,
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


class ProcVisibilityTests(unittest.TestCase):
    def _mountinfo(self, line):
        mountinfo = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        mountinfo.write(line + "\n")
        mountinfo.flush()
        return mountinfo

    def test_default_proc_mount_exposes_other_users_process_metadata(self):
        line = "25 29 0:23 / /proc rw,nosuid,nodev,noexec - proc proc rw"
        with self._mountinfo(line) as mountinfo:
            self.assertEqual(scan_proc_hidepid(mountinfo.name), 0)

        with patch("hardaudit.scan_proc_hidepid", return_value=0):
            findings = [f for f in audit_filesystem().findings if "processus" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("multi-utilisateur", findings[0].detail)

    def test_representative_hidepid_modes_protect_process_metadata(self):
        for value, expected in (("1", 1), ("invisible", 2), ("ptraceable", 4)):
            with self.subTest(value=value):
                line = f"25 29 0:23 / /proc rw,nosuid,nodev,noexec - proc proc rw,hidepid={value}"
                with self._mountinfo(line) as mountinfo:
                    self.assertEqual(scan_proc_hidepid(mountinfo.name), expected)

    def test_live_proc_mount_is_parsed_without_modifying_it(self):
        mode = scan_proc_hidepid()
        self.assertIn(mode, (0, 1, 2, 4, None))


class SharedMemoryMountTests(unittest.TestCase):
    def _mountinfo(self, line):
        mountinfo = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        mountinfo.write(line + "\n")
        mountinfo.flush()
        return mountinfo

    def test_missing_noexec_is_reported(self):
        line = "42 29 0:28 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw,inode64"
        with self._mountinfo(line) as mountinfo:
            self.assertEqual(
                scan_mount_options("/dev/shm", mountinfo.name),
                {"rw", "nosuid", "nodev", "inode64"},
            )

        with patch(
            "hardaudit.scan_mount_options",
            return_value={"rw", "nosuid", "nodev"},
        ):
            findings = [f for f in audit_filesystem().findings if "/dev/shm" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("noexec", findings[0].detail)

    def test_representative_hardened_mount_passes(self):
        line = "42 29 0:28 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw,inode64"
        with self._mountinfo(line) as mountinfo:
            options = scan_mount_options("/dev/shm", mountinfo.name)
        self.assertTrue({"nodev", "nosuid", "noexec"}.issubset(options))

        with patch("hardaudit.scan_mount_options", return_value=options):
            findings = [f for f in audit_filesystem().findings if "/dev/shm" in f.title]
        self.assertEqual(findings, [])

    def test_live_mount_is_exercised_read_only(self):
        options = scan_mount_options("/dev/shm")
        if options is None:
            self.skipTest("/dev/shm is not a distinct mount")
        self.assertIn("rw", options)


class ReversePathFilteringTests(unittest.TestCase):
    def _write_rp_filter(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        with open(os.path.join(interface_dir, "rp_filter"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_reports_only_interfaces_with_no_effective_source_validation(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_rp_filter(root, "all", 0)
            self._write_rp_filter(root, "default", 0)
            self._write_rp_filter(root, "eth0", 0)
            self._write_rp_filter(root, "eth1", 2)
            self._write_rp_filter(root, "lo", 0)
            self.assertEqual(
                scan_unprotected_reverse_paths(root),
                [("eth0", 0, 0)],
            )

    def test_all_loose_mode_protects_interfaces_even_when_local_value_is_zero(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_rp_filter(root, "all", 2)
            self._write_rp_filter(root, "default", 2)
            self._write_rp_filter(root, "eth0", 0)
            self._write_rp_filter(root, "lo", 0)
            self.assertEqual(scan_unprotected_reverse_paths(root), [])

    @patch("hardaudit._capture", return_value=(0, ""))
    @patch("hardaudit.scan_unprotected_reverse_paths", return_value=[("eth0", 0, 0)])
    def test_network_audit_reports_disabled_source_validation(self, _scan, _capture):
        findings = [f for f in audit_network().findings if "anti-spoofing" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("routage asymetrique", findings[0].detail)

    def test_representative_host_values_are_exercised_safely(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "rp_filter")):
            self.skipTest("rp_filter is not exposed by this kernel")
        findings = scan_unprotected_reverse_paths(root)
        self.assertIsInstance(findings, list)
        for interface, all_value, interface_value in findings:
            self.assertNotEqual(interface, "lo")
            self.assertEqual(max(all_value, interface_value), 0)


class IcmpRedirectTests(unittest.TestCase):
    def _write_interface(self, root, interface, accept_redirects, forwarding):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (
            ("accept_redirects", accept_redirects),
            ("forwarding", forwarding),
        ):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_host_interface_can_accept_redirects_even_when_all_is_zero(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 0, 0)
            self._write_interface(root, "default", 0, 0)
            self._write_interface(root, "eth0", 1, 0)
            self._write_interface(root, "lo", 1, 0)
            self.assertEqual(
                scan_unsafe_ipv4_redirects(root),
                [("eth0", 0, 1, 0)],
            )

        with patch(
            "hardaudit.scan_unsafe_ipv4_redirects",
            return_value=[("eth0", 0, 1, 0)],
        ), patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[]):
            findings = [f for f in audit_network().findings if "redirects ICMP" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("eth0", findings[0].detail)

    def test_router_requires_both_all_and_interface_to_accept_redirects(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 0, 1)
            self._write_interface(root, "default", 0, 1)
            self._write_interface(root, "eth0", 1, 1)
            self._write_interface(root, "lo", 1, 1)
            self.assertEqual(scan_unsafe_ipv4_redirects(root), [])

    def test_live_values_are_evaluated_without_modification(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "accept_redirects")):
            self.skipTest("IPv4 redirect controls are not exposed by this kernel")
        findings = scan_unsafe_ipv4_redirects(root)
        self.assertIsInstance(findings, list)
        for interface, all_value, interface_value, forwarding in findings:
            self.assertNotIn(interface, ("all", "default", "lo"))
            expected = (
                all_value == 1 and interface_value == 1
                if forwarding == 1
                else all_value == 1 or interface_value == 1
            )
            self.assertTrue(expected)


class IcmpRedirectSenderTests(unittest.TestCase):
    def _write_interface(self, root, interface, send_redirects, forwarding):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (
            ("send_redirects", send_redirects),
            ("forwarding", forwarding),
        ):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_local_value_enables_redirects_even_when_all_is_zero(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 0, 1)
            self._write_interface(root, "default", 0, 1)
            self._write_interface(root, "eth0", 1, 1)
            self._write_interface(root, "eth1", 0, 1)
            self._write_interface(root, "lo", 1, 1)
            self.assertEqual(
                scan_unsafe_ipv4_redirect_senders(root),
                [("eth0", 0, 1, 1)],
            )

        with patch(
            "hardaudit.scan_unsafe_ipv4_redirect_senders",
            return_value=[("eth0", 0, 1, 1)],
        ), patch("hardaudit.scan_unsafe_ipv4_redirects", return_value=[]):
            findings = [f for f in audit_network().findings if "Emission effective" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("eth0", findings[0].detail)

    def test_non_router_does_not_send_redirects_even_when_sysctl_is_enabled(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 1, 0)
            self._write_interface(root, "default", 1, 0)
            self._write_interface(root, "eth0", 1, 0)
            self._write_interface(root, "lo", 1, 0)
            self.assertEqual(scan_unsafe_ipv4_redirect_senders(root), [])

    def test_live_values_are_evaluated_without_modification(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "send_redirects")):
            self.skipTest("IPv4 redirect sender controls are not exposed by this kernel")
        findings = scan_unsafe_ipv4_redirect_senders(root)
        self.assertIsInstance(findings, list)
        for interface, all_value, interface_value, forwarding in findings:
            self.assertNotIn(interface, ("all", "default", "lo"))
            self.assertEqual(forwarding, 1)
            self.assertTrue(all_value == 1 or interface_value == 1)


class SuidCoreDumpTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_debug_mode_exposes_privileged_process_memory(self):
        with self._sysctl(1) as mode, self._sysctl("core") as pattern:
            self.assertEqual(
                scan_unsafe_suid_dumps(mode.name, pattern.name),
                (1, "core"),
            )

    def test_suidsafe_mode_requires_pipe_or_absolute_path(self):
        with self._sysctl(2) as mode, self._sysctl("core.%p") as pattern:
            self.assertEqual(
                scan_unsafe_suid_dumps(mode.name, pattern.name),
                (2, "core.%p"),
            )

    def test_representative_apport_pipe_is_accepted(self):
        apport = "|/usr/share/apport/apport -p%p -s%s -- %E"
        with self._sysctl(2) as mode, self._sysctl(apport) as pattern:
            self.assertIsNone(scan_unsafe_suid_dumps(mode.name, pattern.name))

        with patch("hardaudit.scan_unsafe_suid_dumps", return_value=None):
            findings = [f for f in audit_kernel().findings if "Core dumps SUID" in f.title]
        self.assertEqual(findings, [])


class UnprivilegedBpfTests(unittest.TestCase):
    def test_enabled_unprivileged_bpf_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_unprivileged_bpf(sysctl.name), 0)

        with patch("hardaudit.scan_unprivileged_bpf", return_value=0):
            findings = [f for f in audit_kernel().findings
                        if f.title == "BPF accessible aux utilisateurs non privilegies"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_representative_ubuntu_default_disables_unprivileged_bpf(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("2\n")
            sysctl.flush()
            self.assertIsNone(scan_unprivileged_bpf(sysctl.name))


class BpfJitHardeningTests(unittest.TestCase):
    def test_disabled_jit_hardening_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(hardaudit.scan_bpf_jit_hardening(sysctl.name), 0)

        with patch("hardaudit.scan_bpf_jit_hardening", return_value=0):
            findings = [f for f in audit_kernel().findings if "JIT BPF" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("JIT spraying", findings[0].detail)

    def test_representative_all_user_hardening_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("2\n")
            sysctl.flush()
            self.assertIsNone(hardaudit.scan_bpf_jit_hardening(sysctl.name))

    def test_unprivileged_only_mode_remains_visible(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertEqual(hardaudit.scan_bpf_jit_hardening(sysctl.name), 1)


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


class AppArmorIoUringMediationTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_available_but_disabled_mediation_is_reported(self):
        with self._sysctl(0) as global_policy, self._sysctl(0) as apparmor_policy:
            self.assertEqual(
                scan_unmediated_unprivileged_io_uring(
                    global_policy.name, apparmor_policy.name
                ),
                (0, 0),
            )

        with patch(
            "hardaudit.scan_unmediated_unprivileged_io_uring", return_value=(0, 0)
        ):
            findings = [
                f for f in audit_kernel().findings if "mediation AppArmor" in f.detail
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_apparmor_mediation_passes(self):
        with self._sysctl(0) as global_policy, self._sysctl(1) as apparmor_policy:
            self.assertIsNone(scan_unmediated_unprivileged_io_uring(
                global_policy.name, apparmor_policy.name
            ))

    def test_global_restriction_makes_apparmor_fallback_unnecessary(self):
        with self._sysctl(1) as global_policy, self._sysctl(0) as apparmor_policy:
            self.assertIsNone(scan_unmediated_unprivileged_io_uring(
                global_policy.name, apparmor_policy.name
            ))

    def test_missing_apparmor_interface_is_not_called_disabled(self):
        with self._sysctl(0) as global_policy:
            self.assertIsNone(scan_unmediated_unprivileged_io_uring(
                global_policy.name, "/path/that/does/not/exist"
            ))


class UserfaultfdRestrictionTests(unittest.TestCase):
    def test_unrestricted_userfaultfd_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertEqual(scan_unprivileged_userfaultfd(sysctl.name), 1)

        with patch("hardaudit.scan_unprivileged_userfaultfd", return_value=1):
            findings = [f for f in audit_kernel().findings if "userfaultfd" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("/dev/userfaultfd", findings[0].detail)

    def test_representative_kernel_default_restricts_userfaultfd(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertIsNone(scan_unprivileged_userfaultfd(sysctl.name))


class MemfdExecutionPolicyTests(unittest.TestCase):
    def test_legacy_executable_default_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_executable_memfd_default(sysctl.name), 0)

        with patch("hardaudit.scan_executable_memfd_default", return_value=0):
            findings = [f for f in audit_kernel().findings if "memfd" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("MFD_EXEC", findings[0].detail)

    def test_representative_explicit_and_enforced_modes_pass(self):
        for value in ("1\n", "2\n"):
            with self.subTest(value=value.strip()):
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
                    sysctl.write(value)
                    sysctl.flush()
                    self.assertIsNone(scan_executable_memfd_default(sysctl.name))


class AppArmorUserNamespaceRestrictionTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_enabled_userns_without_apparmor_restriction_is_reported(self):
        with self._sysctl(1) as userns, self._sysctl(0) as restriction:
            self.assertEqual(
                scan_unrestricted_unprivileged_userns(userns.name, restriction.name),
                (1, 0),
            )

        with patch("hardaudit.scan_unrestricted_unprivileged_userns", return_value=(1, 0)):
            findings = [f for f in audit_kernel().findings if "namespaces utilisateur" in f.title.lower()]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("AppArmor", findings[0].detail)

    def test_representative_ubuntu_apparmor_restriction_passes(self):
        with self._sysctl(1) as userns, self._sysctl(1) as restriction:
            self.assertIsNone(
                scan_unrestricted_unprivileged_userns(userns.name, restriction.name)
            )

    def test_disabled_user_namespaces_pass_even_without_apparmor_restriction(self):
        with self._sysctl(0) as userns, self._sysctl(0) as restriction:
            self.assertIsNone(
                scan_unrestricted_unprivileged_userns(userns.name, restriction.name)
            )


class NullPageMappingTests(unittest.TestCase):
    def test_zero_floor_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_zero_page_mappable(sysctl.name), 0)

        with patch("hardaudit.scan_zero_page_mappable", return_value=0):
            findings = [f for f in audit_kernel().findings if "Page memoire nulle" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("65536", findings[0].detail)

    def test_representative_linux_floor_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("65536\n")
            sysctl.flush()
            self.assertIsNone(scan_zero_page_mappable(sysctl.name))


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


class LegacyTiocstiTests(unittest.TestCase):
    def test_legacy_terminal_injection_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertEqual(scan_legacy_tiocsti_enabled(sysctl.name), 1)

        with patch("hardaudit.scan_legacy_tiocsti_enabled", return_value=1):
            findings = [f for f in audit_kernel().findings if "TIOCSTI" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_hardened_value_blocks_legacy_injection(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertIsNone(scan_legacy_tiocsti_enabled(sysctl.name))


class KexecRestrictionTests(unittest.TestCase):
    def test_enabled_kexec_is_reported_with_irreversible_warning(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(scan_kexec_enabled(sysctl.name), 0)

        with patch("hardaudit.scan_kexec_enabled", return_value=0):
            findings = [f for f in audit_kernel().findings if "kexec" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("irreversible", findings[0].detail)

    def test_representative_locked_production_host_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertIsNone(scan_kexec_enabled(sysctl.name))


class KernelModuleLoadingLockTests(unittest.TestCase):
    def test_unlocked_module_loading_is_reported_with_irreversible_warning(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("0\n")
            sysctl.flush()
            self.assertEqual(hardaudit.scan_module_loading_unlocked(sysctl.name), 0)

        with patch("hardaudit.scan_module_loading_unlocked", return_value=0):
            findings = [f for f in audit_kernel().findings if "modules noyau" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("irreversible", findings[0].detail)

    def test_representative_immutable_appliance_blocks_module_changes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysctl:
            sysctl.write("1\n")
            sysctl.flush()
            self.assertIsNone(hardaudit.scan_module_loading_unlocked(sysctl.name))


class KernelLockdownTests(unittest.TestCase):
    def test_available_but_disabled_lockdown_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as status:
            status.write("[none] integrity confidentiality\n")
            status.flush()
            self.assertEqual(scan_kernel_lockdown_disabled(status.name), "none")

        with patch("hardaudit.scan_kernel_lockdown_disabled", return_value="none"):
            findings = [f for f in audit_kernel().findings if "Lockdown" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_integrity_mode_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as status:
            status.write("none [integrity] confidentiality\n")
            status.flush()
            self.assertIsNone(scan_kernel_lockdown_disabled(status.name))

    def test_missing_interface_is_not_called_disabled(self):
        self.assertIsNone(scan_kernel_lockdown_disabled("/path/that/does/not/exist"))


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

    @patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[])
    @patch("hardaudit.scan_unsafe_ipv4_redirects", return_value=[])
    @patch("hardaudit.scan_unprotected_reverse_paths", return_value=[])
    @patch("hardaudit._capture")
    def test_allowed_port_stays_visible_without_penalty(self, capture, _rp, _accept, _send):
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

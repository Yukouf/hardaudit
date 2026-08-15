import ctypes
import os
import shutil
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
    audit_services,
    audit_users,
    classify_deleted_executable,
    classify_update_severity,
    extract_unreviewed_wildcard_ports,
    firewall_has_default_deny,
    print_finding,
    get_effective_sshd_settings,
    kernel_sysctl_is_unsafe,
    scan_active_lsms,
    scan_kernel_lockdown_disabled,
    scan_binfmt_credential_entries,
    scan_kexec_enabled,
    scan_unlimited_kexec_loads,
    scan_executable_memfd_default,
    scan_deleted_executables,
    scan_deleted_executable_mappings,
    scan_fs_link_protections,
    scan_gratuitous_arp_updates,
    scan_unsolicited_arp_learning,
    scan_unicast_ipv4_in_l2_multicast,
    scan_mount_options,
    scan_unlogged_martian_interfaces,
    scan_locally_sourced_ipv4_interfaces,
    scan_proc_hidepid,
    scan_routed_loopback_interfaces,
    scan_unsafe_ipv4_source_routing,
    scan_broad_ipv4_redirect_trust,
    scan_unsafe_ipv4_redirect_senders,
    scan_unsafe_ipv4_redirects,
    scan_unsafe_ipv6_redirects,
    scan_tcp_timewait_assassination,
    scan_ipv6_routers_accepting_ra,
    scan_ipv6_local_router_advertisements,
    scan_unprotected_reverse_paths,
    scan_unsafe_suid_dumps,
    scan_unbounded_core_pipe,
    scan_unsafe_core_pipe_helper,
    scan_unlimited_user_pipe_memory,
    scan_unrestricted_io_uring,
    scan_unmediated_unprivileged_io_uring,
    scan_unprivileged_bpf,
    scan_legacy_tiocsti_enabled,
    scan_unprivileged_tty_ldisc_autoload,
    scan_unprivileged_userfaultfd,
    scan_delegated_userfaultfd,
    scan_unrestricted_unprivileged_userns,
    scan_unconfined_userns_exception,
    scan_unlimited_kernel_oopses,
    scan_unlimited_kernel_warnings,
    scan_destructive_magic_sysrq,
    scan_orphaned_sysv_shared_memory,
    scan_suboptimal_aslr_entropy,
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

    def test_detects_deleted_executable_mapping_without_duplicate_segments(self):
        with tempfile.TemporaryDirectory() as proc:
            process = os.path.join(proc, "4242")
            os.makedirs(process)
            os.symlink("/usr/bin/python3", os.path.join(process, "exe"))
            with open(os.path.join(process, "comm"), "w", encoding="utf-8") as f:
                f.write("python3\n")
            with open(os.path.join(process, "maps"), "w", encoding="utf-8") as f:
                f.write(
                    "7f00-7f01 r-xp 00000000 00:01 7 /tmp/probe.so (deleted)\n"
                    "7f01-7f02 r--p 00001000 00:01 7 /tmp/probe.so (deleted)\n"
                    "7f02-7f03 r-xp 00002000 00:01 7 /tmp/probe.so (deleted)\n"
                )

            self.assertEqual(
                scan_deleted_executable_mappings(proc),
                [{
                    "pid": 4242,
                    "name": "python3",
                    "target": "/tmp/probe.so (deleted)",
                }],
            )

    def test_live_deleted_shared_library_mapping_is_detected_safely(self):
        candidates = (
            "/lib/x86_64-linux-gnu/libz.so.1",
            "/usr/lib/x86_64-linux-gnu/libz.so.1",
            "/lib64/libz.so.1",
        )
        source = next((path for path in candidates if os.path.exists(path)), None)
        if source is None:
            self.skipTest("aucune bibliotheque partagee representative disponible")

        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "hardaudit-probe.so")
            shutil.copy2(source, target)
            library = ctypes.CDLL(target)
            os.unlink(target)
            findings = scan_deleted_executable_mappings()
            self.assertTrue(any(
                item["pid"] == os.getpid() and item["target"] == f"{target} (deleted)"
                for item in findings
            ))
            self.assertIsNotNone(library)

    def test_service_audit_reports_deleted_executable_mapping(self):
        mapping = {
            "pid": 4242,
            "name": "python3",
            "target": "/tmp/probe.so (deleted)",
        }
        with patch("hardaudit.subprocess.run") as run, \
             patch("hardaudit.os.path.exists", return_value=False), \
             patch("hardaudit.scan_deleted_executables", return_value=[]), \
             patch("hardaudit.scan_deleted_executable_mappings", return_value=[mapping]):
            run.return_value.returncode = 1
            findings = [
                finding for finding in audit_services().findings
                if finding.title == "Code supprime encore charge depuis un dossier temporaire"
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("/proc/4242/maps", findings[0].verify)


class FilesystemProtectionTests(unittest.TestCase):
    def _write_sysctls(self, root, values):
        for name, value in values.items():
            with open(os.path.join(root, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_weak_protections_are_reported_but_stronger_value_is_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_sysctls(root, {
                "protected_hardlinks": 0,
                "protected_symlinks": 1,
                "protected_fifos": 1,
                "protected_regular": 2,
            })
            findings = scan_fs_link_protections(root)
            self.assertEqual(
                [finding[0] for finding in findings],
                ["Hardlinks non proteges", "FIFO insuffisamment proteges"],
            )

    def test_representative_hardened_linux_values_pass(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_sysctls(root, {
                "protected_hardlinks": 1,
                "protected_symlinks": 1,
                "protected_fifos": 2,
                "protected_regular": 2,
            })
            self.assertEqual(scan_fs_link_protections(root), [])


class UserPipeMemoryTests(unittest.TestCase):
    def _limit(self, value):
        limit = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        limit.write(f"{value}\n")
        limit.flush()
        return limit

    def test_both_disabled_pipe_quotas_are_reported(self):
        with self._limit(0) as soft, self._limit(0) as hard:
            self.assertEqual(
                scan_unlimited_user_pipe_memory(soft.name, hard.name),
                (0, 0),
            )

        with patch("hardaudit.scan_unlimited_user_pipe_memory", return_value=(0, 0)):
            findings = [f for f in audit_kernel().findings if "memoire des pipes" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("aucune limite", findings[0].detail)

    def test_positive_soft_quota_is_accepted_when_hard_quota_is_disabled(self):
        with self._limit(16384) as soft, self._limit(0) as hard:
            self.assertIsNone(scan_unlimited_user_pipe_memory(soft.name, hard.name))

    def test_live_pipe_quotas_are_read_without_modification(self):
        result = scan_unlimited_user_pipe_memory()
        self.assertIn(result, (None, (0, 0)))


class SplitLockMitigationTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_disabled_mitigation_is_reported(self):
        with self._sysctl(0) as sysctl:
            self.assertEqual(hardaudit.scan_disabled_split_lock_mitigation(sysctl.name), 0)

        with patch("hardaudit.scan_disabled_split_lock_mitigation", return_value=0):
            findings = [f for f in audit_kernel().findings if "split lock" in f.title.lower()]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("deni de service", findings[0].detail)

    def test_representative_enabled_mitigation_passes(self):
        with self._sysctl(1) as sysctl:
            self.assertIsNone(hardaudit.scan_disabled_split_lock_mitigation(sysctl.name))

    def test_live_policy_is_read_without_modification(self):
        result = hardaudit.scan_disabled_split_lock_mitigation()
        self.assertIn(result, (None, 0))


class KernelWarningLimitTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_disabled_panic_and_warning_counter_are_reported(self):
        with self._sysctl(0) as panic, self._sysctl(0) as limit:
            self.assertEqual(
                scan_unlimited_kernel_warnings(panic.name, limit.name),
                (0, 0),
            )

        with patch("hardaudit.scan_unlimited_kernel_warnings", return_value=(0, 0)):
            findings = [
                finding for finding in audit_kernel().findings
                if "warnings kernel" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("compteur desactive", findings[0].detail)

    def test_positive_warning_limit_is_accepted(self):
        with self._sysctl(0) as panic, self._sysctl(100) as limit:
            self.assertIsNone(scan_unlimited_kernel_warnings(panic.name, limit.name))

    def test_panic_on_first_warning_is_accepted(self):
        with self._sysctl(1) as panic, self._sysctl(0) as limit:
            self.assertIsNone(scan_unlimited_kernel_warnings(panic.name, limit.name))

    def test_live_warning_policy_is_read_without_modification(self):
        result = scan_unlimited_kernel_warnings()
        self.assertIn(result, (None, (0, 0)))


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


class RoutedLoopbackTests(unittest.TestCase):
    def _write_route_localnet(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "route_localnet"), "w", encoding="utf-8") as f:
            f.write(str(value))

    def test_detects_only_real_interfaces_that_route_127_over_ipv4(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 1), ("lo", 1),
                ("eth0", 1), ("eth1", 0),
            ):
                self._write_route_localnet(root, interface, value)
            self.assertEqual(scan_routed_loopback_interfaces(root), [("eth0", 0, 1)])

            self._write_route_localnet(root, "all", 1)
            self.assertEqual(
                scan_routed_loopback_interfaces(root),
                [("eth0", 1, 1), ("eth1", 1, 0)],
            )

        with patch("hardaudit.scan_routed_loopback_interfaces", return_value=[("eth0", 0, 1)]):
            findings = [f for f in audit_network().findings if "loopback" in f.title.lower()]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("127/8", findings[0].detail)

    def test_live_route_localnet_values_are_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "route_localnet")):
            self.skipTest("route_localnet is not exposed by this kernel")
        findings = scan_routed_loopback_interfaces(root)
        self.assertTrue(all(all_value == 1 or local_value == 1
                            for _, all_value, local_value in findings))


class AcceptLocalIPv4Tests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "accept_local"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_global_or_interface_value_accepts_locally_sourced_packets(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 1), ("lo", 1),
                ("eth0", 1), ("eth1", 0),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(
                scan_locally_sourced_ipv4_interfaces(root),
                [("eth0", 0, 1)],
            )

            self._write_value(root, "all", 1)
            self.assertEqual(
                scan_locally_sourced_ipv4_interfaces(root),
                [("eth0", 1, 1), ("eth1", 1, 0)],
            )

        with patch(
            "hardaudit.scan_locally_sourced_ipv4_interfaces",
            return_value=[("eth0", 0, 1)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "source ipv4 locale" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("eth0", findings[0].detail)

    def test_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "accept_local")):
            self.skipTest("accept_local is not exposed by this kernel")
        findings = scan_locally_sourced_ipv4_interfaces(root)
        self.assertTrue(all(all_value == 1 or local_value == 1
                            for _, all_value, local_value in findings))


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


class IPv4SourceRoutingTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "accept_source_route"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_requires_global_and_interface_values_to_accept_source_routes(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 1), ("lo", 1),
                ("eth0", 1), ("eth1", 0),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(scan_unsafe_ipv4_source_routing(root), [])

            self._write_value(root, "all", 1)
            self.assertEqual(
                scan_unsafe_ipv4_source_routing(root),
                [("eth0", 1, 1)],
            )

        with patch(
            "hardaudit.scan_unsafe_ipv4_source_routing",
            return_value=[("eth0", 1, 1)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "impose par la source" in finding.title
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("SRR", findings[0].detail)

    def test_representative_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "accept_source_route")):
            self.skipTest("accept_source_route is not exposed by this kernel")
        findings = scan_unsafe_ipv4_source_routing(root)
        self.assertTrue(all(global_value == 1 and local_value == 1
                            for _, global_value, local_value in findings))


class GratuitousArpTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(
            os.path.join(interface_dir, "drop_gratuitous_arp"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(f"{value}\n")

    def test_global_or_interface_policy_blocks_gratuitous_arp(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 0), ("lo", 0),
                ("eth0", 0), ("eth1", 1),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(
                scan_gratuitous_arp_updates(root),
                [("eth0", 0, 0)],
            )

            self._write_value(root, "all", 1)
            self.assertEqual(scan_gratuitous_arp_updates(root), [])

    def test_network_audit_reports_neighbor_cache_update_surface(self):
        with patch(
            "hardaudit.scan_gratuitous_arp_updates",
            return_value=[("eth0", 0, 0)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "ARP gratuitous" in finding.title
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("cache voisin", findings[0].detail)

    def test_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "drop_gratuitous_arp")):
            self.skipTest("drop_gratuitous_arp is not exposed by this kernel")
        findings = scan_gratuitous_arp_updates(root)
        self.assertTrue(all(
            global_value == 0 and local_value == 0
            for _, global_value, local_value in findings
        ))


class UnsolicitedArpLearningTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "arp_accept"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_effective_policy_uses_maximum_of_global_and_local_modes(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 1), ("default", 0), ("lo", 2),
                ("eth0", 0), ("eth1", 2),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(
                scan_unsolicited_arp_learning(root),
                [("eth0", 1, 0, 1), ("eth1", 1, 2, 2)],
            )

    def test_network_audit_reports_new_neighbor_learning(self):
        with patch(
            "hardaudit.scan_unsolicited_arp_learning",
            return_value=[("eth0", 0, 1, 1)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "voisins par arp non sollicite" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("eth0 (mode 1)", findings[0].detail)

    def test_representative_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "arp_accept")):
            self.skipTest("arp_accept is not exposed by this kernel")
        findings = scan_unsolicited_arp_learning(root)
        self.assertTrue(all(
            effective == max(global_value, local_value) and effective in (1, 2)
            for _, global_value, local_value, effective in findings
        ))


class UnicastIPv4InL2MulticastTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(
            os.path.join(interface_dir, "drop_unicast_in_l2_multicast"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(f"{value}\n")

    def test_global_or_interface_policy_rejects_l2_l3_destination_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 0), ("lo", 0),
                ("eth0", 0), ("wlan0", 1),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(
                scan_unicast_ipv4_in_l2_multicast(root),
                [("eth0", 0, 0)],
            )

            self._write_value(root, "all", 1)
            self.assertEqual(scan_unicast_ipv4_in_l2_multicast(root), [])

    def test_network_audit_reports_l2_l3_destination_mismatch(self):
        with patch(
            "hardaudit.scan_unicast_ipv4_in_l2_multicast",
            return_value=[("wlan0", 0, 0)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "trames l2 multicast" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("wlan0", findings[0].detail)
        self.assertIn("Wi-Fi", findings[0].detail)

    def test_representative_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(
            os.path.join(root, "all", "drop_unicast_in_l2_multicast")
        ):
            self.skipTest("drop_unicast_in_l2_multicast is not exposed by this kernel")
        findings = scan_unicast_ipv4_in_l2_multicast(root)
        self.assertTrue(all(
            global_value == 0 and local_value == 0
            for _, global_value, local_value in findings
        ))


class IPv6SourceRoutingTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "accept_source_route"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_requires_non_negative_global_and_interface_values(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (
                ("all", 0), ("default", 0), ("lo", 0),
                ("eth0", 0), ("eth1", -1), ("eth2", 1),
            ):
                self._write_value(root, interface, value)
            self.assertEqual(
                hardaudit.scan_unsafe_ipv6_source_routing(root),
                [("eth0", 0, 0), ("eth2", 0, 1)],
            )

            self._write_value(root, "all", -1)
            self.assertEqual(hardaudit.scan_unsafe_ipv6_source_routing(root), [])

    def test_network_audit_reports_ipv6_routing_header_acceptance(self):
        with patch(
            "hardaudit.scan_unsafe_ipv6_source_routing",
            return_value=[("eth0", 0, 0)],
        ):
            findings = [
                finding for finding in audit_network().findings
                if "extension de routage ipv6" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("type 2", findings[0].detail)

    def test_representative_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv6/conf"
        if not os.path.exists(os.path.join(root, "all", "accept_source_route")):
            self.skipTest("IPv6 accept_source_route is not exposed by this kernel")
        findings = hardaudit.scan_unsafe_ipv6_source_routing(root)
        self.assertTrue(all(global_value >= 0 and local_value >= 0
                            for _, global_value, local_value in findings))


class MartianPacketLoggingTests(unittest.TestCase):
    def _write_value(self, root, interface, value):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir, exist_ok=True)
        with open(os.path.join(interface_dir, "log_martians"), "w", encoding="utf-8") as f:
            f.write(f"{value}\n")

    def test_reports_only_interfaces_without_effective_logging(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (("all", 0), ("default", 0), ("lo", 0),
                                     ("eth0", 0), ("eth1", 1)):
                self._write_value(root, interface, value)
            self.assertEqual(scan_unlogged_martian_interfaces(root), [("eth0", 0, 0)])

    def test_representative_global_policy_enables_every_interface(self):
        with tempfile.TemporaryDirectory() as root:
            for interface, value in (("all", 1), ("default", 0), ("eth0", 0), ("eth1", 0)):
                self._write_value(root, interface, value)
            self.assertEqual(scan_unlogged_martian_interfaces(root), [])

    def test_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        if not os.path.exists(os.path.join(root, "all", "log_martians")):
            self.skipTest("log_martians is not exposed by this kernel")
        findings = scan_unlogged_martian_interfaces(root)
        self.assertTrue(all(all_value == 0 and local_value == 0
                            for _, all_value, local_value in findings))


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
        ), patch(
            "hardaudit.scan_broad_ipv4_redirect_trust", return_value=[]
        ), patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[]), \
                patch("hardaudit.scan_unsafe_ipv6_redirects", return_value=[]):
            findings = [f for f in audit_network().findings if "ICMP IPv4" in f.title]
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

    def _write_redirect_policy(self, root, interface, accept, forwarding, shared, secure):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (
            ("accept_redirects", accept),
            ("forwarding", forwarding),
            ("shared_media", shared),
            ("secure_redirects", secure),
        ):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_shared_media_overrides_secure_redirect_gateway_check(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_redirect_policy(root, "all", 0, 0, 1, 1)
            self._write_redirect_policy(root, "default", 0, 0, 1, 1)
            self._write_redirect_policy(root, "eth0", 1, 0, 0, 1)
            self._write_redirect_policy(root, "eth1", 0, 0, 0, 1)
            self._write_redirect_policy(root, "lo", 1, 0, 1, 1)
            self.assertEqual(
                scan_broad_ipv4_redirect_trust(root),
                [("eth0", 1, 0, 1, 1)],
            )

        with patch(
            "hardaudit.scan_unsafe_ipv4_redirects", return_value=[("eth0", 0, 1, 0)]
        ), patch(
            "hardaudit.scan_broad_ipv4_redirect_trust",
            return_value=[("eth0", 1, 0, 1, 1)],
        ), patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[]), \
                patch("hardaudit.scan_unsafe_ipv6_redirects", return_value=[]):
            finding = next(
                f for f in audit_network().findings
                if f.title == "Acceptation effective des redirects ICMP IPv4"
            )
        self.assertIn("shared_media outrepasse", finding.detail)

    def test_secure_redirects_restricts_active_policy_when_shared_media_is_off(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_redirect_policy(root, "all", 0, 0, 0, 1)
            self._write_redirect_policy(root, "default", 0, 0, 0, 1)
            self._write_redirect_policy(root, "eth0", 1, 0, 0, 0)
            self.assertEqual(scan_broad_ipv4_redirect_trust(root), [])

    def test_live_redirect_trust_is_evaluated_read_only(self):
        root = "/proc/sys/net/ipv4/conf"
        required = ("accept_redirects", "forwarding", "shared_media", "secure_redirects")
        if not all(os.path.exists(os.path.join(root, "all", name)) for name in required):
            self.skipTest("IPv4 redirect trust controls are not exposed by this kernel")
        findings = scan_broad_ipv4_redirect_trust(root)
        for interface, shared_all, shared_local, secure_all, secure_local in findings:
            self.assertNotIn(interface, ("all", "default", "lo"))
            self.assertTrue(
                shared_all == 1
                or shared_local == 1
                or not (secure_all == 1 or secure_local == 1)
            )

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


class IcmpV6RedirectTests(unittest.TestCase):
    def _write_interface(self, root, interface, accept_redirects, forwarding):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (
            ("accept_redirects", accept_redirects),
            ("forwarding", forwarding),
        ):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_only_host_interfaces_accepting_redirects_are_reported(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 0, 0)
            self._write_interface(root, "default", 0, 0)
            self._write_interface(root, "eth0", 1, 0)
            self._write_interface(root, "eth1", 1, 1)
            self._write_interface(root, "eth2", 0, 0)
            self._write_interface(root, "lo", 1, 0)
            self.assertEqual(scan_unsafe_ipv6_redirects(root), [("eth0", 1, 0)])

        with patch("hardaudit.scan_unsafe_ipv6_redirects", return_value=[("eth0", 1, 0)]), \
                patch("hardaudit.scan_unsafe_ipv4_redirects", return_value=[]), \
                patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[]), \
                patch("hardaudit.scan_unprotected_reverse_paths", return_value=[]), \
                patch("hardaudit.scan_routed_loopback_interfaces", return_value=[]):
            findings = [f for f in audit_network().findings if "ICMPv6" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("eth0", findings[0].detail)

    def test_live_ipv6_values_are_exercised_read_only(self):
        root = "/proc/sys/net/ipv6/conf"
        if not os.path.exists(root):
            self.skipTest("IPv6 controls are not exposed by this kernel")
        findings = scan_unsafe_ipv6_redirects(root)
        self.assertIsInstance(findings, list)
        for interface, accept_redirects, forwarding in findings:
            self.assertNotIn(interface, ("all", "default", "lo"))
            self.assertEqual((accept_redirects, forwarding), (1, 0))


class IPv6RouterAdvertisementTests(unittest.TestCase):
    def _write_interface(self, root, interface, accept_ra, forwarding):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (("accept_ra", accept_ra), ("forwarding", forwarding)):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_only_forwarding_interfaces_with_override_mode_are_reported(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 2, 1)
            self._write_interface(root, "default", 2, 1)
            self._write_interface(root, "eth0", 2, 1)
            self._write_interface(root, "eth1", 1, 1)
            self._write_interface(root, "eth2", 2, 0)
            self._write_interface(root, "lo", 2, 1)
            self.assertEqual(scan_ipv6_routers_accepting_ra(root), [("eth0", 2, 1)])

        with patch("hardaudit.scan_ipv6_routers_accepting_ra", return_value=[("eth0", 2, 1)]), \
                patch("hardaudit.scan_unsafe_ipv6_redirects", return_value=[]):
            findings = [f for f in audit_network().findings if "Router Advertisement" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("eth0", findings[0].detail)

    def test_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv6/conf"
        if not os.path.exists(root):
            self.skipTest("IPv6 controls are not exposed by this kernel")
        findings = scan_ipv6_routers_accepting_ra(root)
        self.assertTrue(all(accept_ra == 2 and forwarding == 1
                            for _, accept_ra, forwarding in findings))


class IPv6LocalRouterAdvertisementTests(unittest.TestCase):
    def _write_interface(self, root, interface, accept_ra, forwarding, accept_from_local):
        interface_dir = os.path.join(root, interface)
        os.makedirs(interface_dir)
        for name, value in (
            ("accept_ra", accept_ra),
            ("forwarding", forwarding),
            ("accept_ra_from_local", accept_from_local),
        ):
            with open(os.path.join(interface_dir, name), "w", encoding="utf-8") as f:
                f.write(f"{value}\n")

    def test_reports_only_interfaces_that_accept_ra_from_a_local_address(self):
        with tempfile.TemporaryDirectory() as root:
            self._write_interface(root, "all", 1, 0, 1)
            self._write_interface(root, "default", 1, 0, 1)
            self._write_interface(root, "eth0", 1, 0, 1)
            self._write_interface(root, "eth1", 1, 0, 0)
            self._write_interface(root, "eth2", 1, 1, 1)
            self._write_interface(root, "eth3", 2, 1, 1)
            self._write_interface(root, "lo", 1, 0, 1)
            self.assertEqual(
                scan_ipv6_local_router_advertisements(root),
                [("eth0", 1, 0, 1), ("eth3", 2, 1, 1)],
            )

    def test_network_audit_reports_local_source_ra_acceptance(self):
        with patch(
            "hardaudit.scan_ipv6_local_router_advertisements",
            return_value=[("eth0", 1, 0, 1)],
        ), patch("hardaudit.scan_ipv6_routers_accepting_ra", return_value=[]):
            findings = [
                finding for finding in audit_network().findings
                if "source locale" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("boucle", findings[0].detail)

    def test_live_policy_is_exercised_read_only(self):
        root = "/proc/sys/net/ipv6/conf"
        if not os.path.exists(os.path.join(root, "all", "accept_ra_from_local")):
            self.skipTest("accept_ra_from_local is not exposed by this kernel")
        findings = scan_ipv6_local_router_advertisements(root)
        self.assertTrue(all(
            accept_from_local == 1
            and (accept_ra == 2 or (accept_ra == 1 and forwarding == 0))
            for _, accept_ra, forwarding, accept_from_local in findings
        ))


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


class CpuMitigationBootPolicyTests(unittest.TestCase):
    def _cmdline(self, value):
        cmdline = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        cmdline.write(value + "\n")
        cmdline.flush()
        return cmdline

    def test_global_cpu_mitigation_opt_out_is_reported(self):
        with self._cmdline("BOOT_IMAGE=/vmlinuz quiet mitigations=off audit=1") as cmdline:
            self.assertEqual(
                hardaudit.scan_disabled_cpu_mitigations(cmdline.name),
                "mitigations=off",
            )

        with patch(
            "hardaudit.scan_disabled_cpu_mitigations",
            return_value="mitigations=off",
        ):
            findings = [
                finding for finding in audit_kernel().findings
                if "CPU" in finding.title and "desactivees" in finding.title
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("Spectre", findings[0].detail)

    def test_default_auto_policy_passes(self):
        with self._cmdline("BOOT_IMAGE=/vmlinuz root=/dev/vda1 quiet") as cmdline:
            self.assertIsNone(hardaudit.scan_disabled_cpu_mitigations(cmdline.name))

    def test_similar_but_unrelated_parameter_does_not_match(self):
        with self._cmdline("foo=mitigations=off mitigations=auto") as cmdline:
            self.assertIsNone(hardaudit.scan_disabled_cpu_mitigations(cmdline.name))

    def test_live_cmdline_is_read_without_modification(self):
        result = hardaudit.scan_disabled_cpu_mitigations()
        self.assertIn(result, (None, "mitigations=off"))


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


class CorePipeLimitTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_unlimited_piped_core_helpers_are_reported(self):
        pattern_value = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"
        with self._sysctl(pattern_value) as pattern, self._sysctl(0) as limit:
            self.assertEqual(
                scan_unbounded_core_pipe(pattern.name, limit.name),
                (pattern_value, 0),
            )

        with patch("hardaudit.scan_unbounded_core_pipe", return_value=(pattern_value, 0)):
            findings = [
                finding for finding in audit_kernel().findings
                if "core dump" in finding.title.lower() and "simultanes" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_bounded_apport_pipe_passes(self):
        pattern_value = "|/usr/share/apport/apport -p%p -s%s -- %E"
        with self._sysctl(pattern_value) as pattern, self._sysctl(10) as limit:
            self.assertIsNone(scan_unbounded_core_pipe(pattern.name, limit.name))

    def test_regular_core_file_does_not_need_a_pipe_limit(self):
        with self._sysctl("core.%p") as pattern, self._sysctl(0) as limit:
            self.assertIsNone(scan_unbounded_core_pipe(pattern.name, limit.name))


class CorePipeHelperPermissionsTests(unittest.TestCase):
    def _pattern(self, value):
        pattern = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        pattern.write(value + "\n")
        pattern.flush()
        return pattern

    def test_world_writable_helper_is_reported_as_root_execution_path(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "collector")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o777)
            with self._pattern(f"|{helper} %P") as pattern:
                result = scan_unsafe_core_pipe_helper(pattern.name)
            self.assertEqual(result[:3], (helper, helper, 0o777))

        with patch(
            "hardaudit.scan_unsafe_core_pipe_helper",
            return_value=("/opt/collector", "/opt/collector", 0o777, 0, 0),
        ):
            findings = [f for f in audit_kernel().findings if "Helper de core dump" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("credentials root", findings[0].detail)

    def test_representative_root_owned_non_writable_helper_passes(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "collector")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o755)
            with self._pattern(f"|{helper} %P") as pattern:
                self.assertIsNone(scan_unsafe_core_pipe_helper(pattern.name))

    def test_live_core_helper_path_is_exercised_read_only(self):
        result = scan_unsafe_core_pipe_helper()
        if result is not None:
            _, _, mode, uid, _ = result
            self.assertTrue(uid != 0 or mode & 0o022)


class ModuleAutoloadHelperTests(unittest.TestCase):
    def _policy(self, value):
        policy = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        policy.write(value + "\n")
        policy.flush()
        return policy

    def test_world_writable_modprobe_helper_is_reported(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "modprobe-helper")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o777)
            with self._policy(helper) as policy:
                result = hardaudit.scan_unsafe_module_helper(policy.name)
            self.assertEqual(result[:3], (helper, helper, 0o777))

        with patch(
            "hardaudit.scan_unsafe_module_helper",
            return_value=("/opt/helper", "/opt/helper", 0o777, 0, 0),
        ):
            findings = [f for f in audit_kernel().findings if "autoload de modules" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("credentials root", findings[0].detail)

    def test_representative_root_owned_helper_and_disabled_autoload_pass(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "modprobe-helper")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o755)
            with self._policy(helper) as policy:
                self.assertIsNone(hardaudit.scan_unsafe_module_helper(policy.name))
        with self._policy("") as policy:
            self.assertIsNone(hardaudit.scan_unsafe_module_helper(policy.name))

    def test_live_modprobe_path_is_exercised_read_only(self):
        result = hardaudit.scan_unsafe_module_helper()
        if result is not None:
            _, _, mode, uid, _ = result
            self.assertTrue(uid != 0 or mode & 0o022)


class HotplugHelperTests(unittest.TestCase):
    def _policy(self, value):
        policy = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        policy.write(value + "\n")
        policy.flush()
        return policy

    def test_world_writable_hotplug_helper_is_critical(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "hotplug-helper")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o777)
            with self._policy(helper) as policy:
                result = hardaudit.scan_enabled_hotplug_helper(policy.name)
            self.assertEqual(result[:3], (helper, helper, 0o777))

        weak = ("/opt/hotplug", "/opt/hotplug", 0o777, 0, 0)
        with patch("hardaudit.scan_enabled_hotplug_helper", return_value=weak):
            findings = [f for f in audit_kernel().findings if "hotplug" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("Chaque uevent", findings[0].detail)

    def test_representative_empty_policy_disables_legacy_helper(self):
        with self._policy("") as policy:
            self.assertIsNone(hardaudit.scan_enabled_hotplug_helper(policy.name))

    def test_root_owned_active_helper_remains_visible_as_legacy_surface(self):
        with tempfile.TemporaryDirectory(dir="/root") as root:
            helper = os.path.join(root, "hotplug-helper")
            with open(helper, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
            os.chmod(helper, 0o755)
            with self._policy(helper) as policy:
                self.assertEqual(
                    hardaudit.scan_enabled_hotplug_helper(policy.name),
                    (helper, None, None, None, None),
                )

    def test_live_hotplug_policy_is_exercised_read_only(self):
        result = hardaudit.scan_enabled_hotplug_helper()
        if result is not None:
            self.assertTrue(result[0])


class OrphanedSysvSharedMemoryTests(unittest.TestCase):
    def _table(self, rows):
        table = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        table.write(
            "key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime rss swap\n"
        )
        for row in rows:
            table.write(" ".join(str(value) for value in row) + "\n")
        table.flush()
        return table

    def test_only_old_unattached_segments_with_dead_creators_are_reported(self):
        with tempfile.TemporaryDirectory() as proc:
            os.mkdir(os.path.join(proc, "222"))
            rows = [
                (0, 11, 600, 4096, 111, 0, 0, 1000, 1000, 1000, 1000, 0, 0, 500, 0, 0),
                (0, 12, 600, 8192, 222, 0, 0, 1000, 1000, 1000, 1000, 0, 0, 500, 0, 0),
                (0, 13, 600, 16384, 333, 0, 1, 1000, 1000, 1000, 1000, 0, 0, 500, 0, 0),
                (0, 14, 600, 32768, 444, 0, 0, 1000, 1000, 1000, 1000, 0, 0, 1900, 0, 0),
            ]
            with self._table(rows) as table:
                self.assertEqual(
                    scan_orphaned_sysv_shared_memory(table.name, proc, 300, now=2000),
                    [{
                        "shmid": 11,
                        "size": 4096,
                        "creator_pid": 111,
                        "owner_uid": 1000,
                        "age_seconds": 1500,
                    }],
                )

        orphan = {
            "shmid": 11, "size": 4096, "creator_pid": 111,
            "owner_uid": 1000, "age_seconds": 7200,
        }
        with patch("hardaudit.scan_orphaned_sysv_shared_memory", return_value=[orphan]):
            findings = [f for f in audit_kernel().findings if "SysV orphelins" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("ipcrm", findings[0].detail)

    def test_representative_segment_really_survives_its_creator(self):
        if not os.path.exists("/proc/sysvipc/shm") or not hasattr(os, "fork"):
            self.skipTest("SysV IPC ou fork indisponible")
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            libc = ctypes.CDLL(None, use_errno=True)
            shmid = libc.shmget(0, 4096, 0o1000 | 0o600)
            os.write(write_fd, str(shmid).encode("ascii"))
            os.close(write_fd)
            os._exit(0 if shmid >= 0 else 1)

        os.close(write_fd)
        shmid_text = os.read(read_fd, 64)
        os.close(read_fd)
        _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0)
        shmid = int(shmid_text)
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            findings = scan_orphaned_sysv_shared_memory(min_age_seconds=0)
            self.assertTrue(any(item["shmid"] == shmid for item in findings))
        finally:
            self.assertEqual(libc.shmctl(shmid, 0, None), 0)


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

    def test_device_permissions_bypass_restrictive_sysctl(self):
        with tempfile.NamedTemporaryFile() as device:
            os.chmod(device.name, 0o666)
            self.assertEqual(scan_delegated_userfaultfd(device.name)[0], 0o666)

        with patch("hardaudit.scan_unprivileged_userfaultfd", return_value=None), \
                patch("hardaudit.scan_delegated_userfaultfd", return_value=(0o660, 0, 1000)):
            findings = [f for f in audit_kernel().findings if "delegue" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertIn("meme si vm.unprivileged_userfaultfd = 0", findings[0].detail)

    def test_representative_root_only_device_passes(self):
        with tempfile.NamedTemporaryFile() as device:
            os.chmod(device.name, 0o600)
            self.assertIsNone(scan_delegated_userfaultfd(device.name))

    def test_live_device_permissions_are_exercised_read_only(self):
        path = "/dev/userfaultfd"
        if not os.path.exists(path):
            self.skipTest("ce kernel n'expose pas /dev/userfaultfd")
        info = os.stat(path)
        expected = None if info.st_uid == 0 and not (info.st_mode & 0o066) \
            else (info.st_mode & 0o777, info.st_uid, info.st_gid)
        self.assertEqual(scan_delegated_userfaultfd(path), expected)


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

    def test_unconfined_profile_exception_is_reported(self):
        with self._sysctl(1) as userns, self._sysctl(1) as restriction, self._sysctl(0) as unconfined:
            self.assertEqual(
                scan_unconfined_userns_exception(
                    userns.name, restriction.name, unconfined.name
                ),
                (1, 1, 0),
            )

        with patch("hardaudit.scan_unconfined_userns_exception", return_value=(1, 1, 0)):
            findings = [f for f in audit_kernel().findings if "unconfined" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("propre permission", findings[0].detail)

    def test_representative_full_apparmor_policy_passes(self):
        with self._sysctl(1) as userns, self._sysctl(1) as restriction, self._sysctl(1) as unconfined:
            self.assertIsNone(
                scan_unconfined_userns_exception(
                    userns.name, restriction.name, unconfined.name
                )
            )

    def test_live_unconfined_policy_is_exercised_read_only(self):
        path = "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined"
        if not os.path.exists(path):
            self.skipTest("ce kernel n'expose pas la politique AppArmor unconfined")
        self.assertIn(scan_unconfined_userns_exception(), ((1, 1, 0), None))

    def test_legacy_policy_abi_bypass_is_reported(self):
        with self._sysctl(1) as userns, self._sysctl(1) as restriction, self._sysctl(0) as force:
            self.assertEqual(
                hardaudit.scan_legacy_apparmor_userns_bypass(
                    userns.name, restriction.name, force.name
                ),
                (1, 1, 0),
            )

        with patch("hardaudit.scan_legacy_apparmor_userns_bypass", return_value=(1, 1, 0)):
            findings = [f for f in audit_kernel().findings if "ABI AppArmor" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("anciennes", findings[0].detail)

    def test_forced_userns_mediation_covers_legacy_policy_abis(self):
        with self._sysctl(1) as userns, self._sysctl(1) as restriction, self._sysctl(1) as force:
            self.assertIsNone(
                hardaudit.scan_legacy_apparmor_userns_bypass(
                    userns.name, restriction.name, force.name
                )
            )

    def test_live_legacy_policy_switch_is_exercised_read_only(self):
        path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns_force"
        if not os.path.exists(path):
            self.skipTest("ce kernel n'expose pas le controle ABI AppArmor userns")
        self.assertIn(
            hardaudit.scan_legacy_apparmor_userns_bypass(),
            ((1, 1, 0), None),
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

    def test_unlimited_normal_and_crash_kexec_loads_are_detected(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as reboot, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as panic:
            reboot.write("-1\n"); reboot.flush()
            panic.write("-1\n"); panic.flush()
            self.assertEqual(
                scan_unlimited_kexec_loads(reboot.name, panic.name),
                ("reboot", "panic"),
            )

    def test_representative_bounded_kexec_policy_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as reboot, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as panic:
            reboot.write("1\n"); reboot.flush()
            panic.write("2\n"); panic.flush()
            self.assertEqual(scan_unlimited_kexec_loads(reboot.name, panic.name), ())

    def test_kexec_finding_reports_unlimited_image_replacement_attempts(self):
        with patch("hardaudit.scan_kexec_enabled", return_value=0), \
                patch("hardaudit.scan_unlimited_kexec_loads", return_value=("reboot", "panic")):
            findings = [f for f in audit_kernel().findings if "kexec" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertIn("sans limite", findings[0].detail)


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


class KernelModuleSignatureTests(unittest.TestCase):
    def _file(self, content):
        handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        handle.write(content)
        handle.flush()
        return handle

    def test_permissive_signature_verification_is_reported(self):
        with self._file("CONFIG_MODULE_SIG=y\n") as config, \
                self._file("quiet splash\n") as cmdline, \
                self._file("0\n") as modules_disabled, \
                self._file("[none] integrity confidentiality\n") as lockdown:
            self.assertEqual(
                hardaudit.scan_permissive_module_signatures(
                    config.name, cmdline.name, modules_disabled.name, lockdown.name
                ),
                "permissive",
            )

        with patch("hardaudit.scan_permissive_module_signatures", return_value="permissive"):
            findings = [f for f in audit_kernel().findings if "non signes" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("CAP_SYS_MODULE", findings[0].detail)

    def test_representative_enforcement_paths_pass(self):
        scenarios = (
            ("CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_FORCE=y\n", "quiet\n", "0\n", "[none] integrity confidentiality\n"),
            ("CONFIG_MODULE_SIG=y\n", "module.sig_enforce=1\n", "0\n", "[none] integrity confidentiality\n"),
            ("CONFIG_MODULE_SIG=y\n", "quiet\n", "0\n", "none [integrity] confidentiality\n"),
            ("CONFIG_MODULE_SIG=y\n", "quiet\n", "1\n", "[none] integrity confidentiality\n"),
        )
        for config_value, cmdline_value, disabled_value, lockdown_value in scenarios:
            with self.subTest(scenario=(config_value, cmdline_value, disabled_value, lockdown_value)), \
                    self._file(config_value) as config, \
                    self._file(cmdline_value) as cmdline, \
                    self._file(disabled_value) as modules_disabled, \
                    self._file(lockdown_value) as lockdown:
                self.assertIsNone(
                    hardaudit.scan_permissive_module_signatures(
                        config.name, cmdline.name, modules_disabled.name, lockdown.name
                    )
                )

    def test_live_policy_is_exercised_read_only(self):
        result = hardaudit.scan_permissive_module_signatures()
        self.assertIn(result, (None, "permissive", "unsupported"))


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


class ActiveLsmTests(unittest.TestCase):
    def test_missing_mandatory_access_control_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as status:
            status.write("lockdown,capability,landlock,yama\n")
            status.flush()
            self.assertEqual(
                scan_active_lsms(status.name),
                ["lockdown", "capability", "landlock", "yama"],
            )

        with patch(
            "hardaudit.scan_active_lsms",
            return_value=["lockdown", "capability", "landlock", "yama"],
        ):
            findings = [f for f in audit_kernel().findings if "LSM" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("politique MAC", findings[0].detail)

    def test_representative_stacked_apparmor_policy_passes(self):
        active = ["lockdown", "capability", "landlock", "yama", "apparmor"]
        with patch("hardaudit.scan_active_lsms", return_value=active):
            findings = [f for f in audit_kernel().findings if "LSM" in f.title]
        self.assertEqual(findings, [])

    def test_live_lsm_stack_is_exercised_read_only(self):
        active = scan_active_lsms()
        if active is None:
            self.skipTest("securityfs ne rend pas la liste LSM accessible")
        self.assertIn("capability", active)
        self.assertEqual(len(active), len(set(active)))


class BinfmtCredentialTests(unittest.TestCase):
    def _entry(self, root, name, flags, state="enabled"):
        with open(os.path.join(root, name), "w", encoding="utf-8") as entry:
            entry.write(
                f"{state}\ninterpreter /usr/libexec/{name}\nflags: {flags}\n"
                "offset 0\nmagic deadbeef\n"
            )

    def test_credential_flag_is_reported_but_regular_entries_are_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            self._entry(root, "risky", "OCF")
            self._entry(root, "qemu-safe", "F")
            self._entry(root, "disabled-c", "C", state="disabled")
            self.assertEqual(
                scan_binfmt_credential_entries(root),
                [("risky", "/usr/libexec/risky", "OCF")],
            )

        with patch(
            "hardaudit.scan_binfmt_credential_entries",
            return_value=[("risky", "/usr/libexec/risky", "OCF")],
        ):
            findings = [f for f in audit_kernel().findings if "binfmt_misc" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("setuid root", findings[0].detail)

    def test_representative_local_registrations_are_exercised_read_only(self):
        findings = scan_binfmt_credential_entries()
        self.assertIsInstance(findings, list)
        for name, interpreter, flags in findings:
            self.assertTrue(name)
            self.assertTrue(interpreter)
            self.assertIn("C", flags)


class KernelStackOffsetRandomizationTests(unittest.TestCase):
    def _file(self, content):
        handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        handle.write(content)
        handle.flush()
        return handle

    def test_disabled_boot_policy_is_reported(self):
        with self._file(
            "CONFIG_RANDOMIZE_KSTACK_OFFSET=y\n"
            "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y\n"
        ) as config, self._file("quiet randomize_kstack_offset=off\n") as cmdline:
            self.assertEqual(
                hardaudit.scan_disabled_kstack_offset_randomization(
                    config.name, cmdline.name
                ),
                (True, "off"),
            )

        with patch(
            "hardaudit.scan_disabled_kstack_offset_randomization",
            return_value=(True, "off"),
        ):
            findings = [
                finding for finding in audit_kernel().findings
                if "pile kernel" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("5 bits", findings[0].detail)

    def test_representative_enabled_default_and_boot_override_pass(self):
        with self._file(
            "CONFIG_RANDOMIZE_KSTACK_OFFSET=y\n"
            "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y\n"
        ) as config, self._file("quiet splash\n") as cmdline:
            self.assertIsNone(
                hardaudit.scan_disabled_kstack_offset_randomization(
                    config.name, cmdline.name
                )
            )

        with self._file(
            "CONFIG_RANDOMIZE_KSTACK_OFFSET=y\n"
        ) as config, self._file("randomize_kstack_offset=on\n") as cmdline:
            self.assertIsNone(
                hardaudit.scan_disabled_kstack_offset_randomization(
                    config.name, cmdline.name
                )
            )

    def test_live_boot_policy_is_exercised_read_only(self):
        result = hardaudit.scan_disabled_kstack_offset_randomization()
        if result is not None:
            default_enabled, override = result
            self.assertIsInstance(default_enabled, bool)
            self.assertIn(override, (None, "0", "n", "no", "false", "off"))


class KernelSysctlSemanticsTests(unittest.TestCase):
    def test_broadcast_echo_responses_are_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as policy:
            policy.write("0\n")
            policy.flush()
            self.assertEqual(hardaudit.scan_broadcast_icmp_echo_enabled(policy.name), 0)

        with patch("hardaudit.scan_broadcast_icmp_echo_enabled", return_value=0):
            findings = [
                finding for finding in audit_network().findings
                if "broadcast" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("amplification", findings[0].detail)

    def test_broadcast_echo_ignore_and_live_policy_are_exercised_read_only(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as policy:
            policy.write("1\n")
            policy.flush()
            self.assertIsNone(hardaudit.scan_broadcast_icmp_echo_enabled(policy.name))

        live = hardaudit.scan_broadcast_icmp_echo_enabled()
        self.assertIn(live, (None, 0))

    def test_disabled_rfc1337_protection_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as policy:
            policy.write("0\n")
            policy.flush()
            self.assertEqual(scan_tcp_timewait_assassination(policy.name), 0)

        with patch("hardaudit.scan_tcp_timewait_assassination", return_value=0):
            findings = [
                finding for finding in audit_network().findings
                if "TIME-WAIT" in finding.title
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("RST", findings[0].detail)

    def test_representative_rfc1337_protection_and_live_policy(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as policy:
            policy.write("1\n")
            policy.flush()
            self.assertIsNone(scan_tcp_timewait_assassination(policy.name))

        live = scan_tcp_timewait_assassination()
        self.assertIn(live, (None, 0))

    def test_aslr_entropy_below_architecture_maximum_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as bits, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as compat, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as config:
            bits.write("28\n"); bits.flush()
            compat.write("16\n"); compat.flush()
            config.write(
                "CONFIG_ARCH_MMAP_RND_BITS_MAX=32\n"
                "CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16\n"
            ); config.flush()
            self.assertEqual(
                scan_suboptimal_aslr_entropy(bits.name, compat.name, config.name),
                [("vm.mmap_rnd_bits", 28, 32)],
            )

    def test_representative_maximum_aslr_entropy_is_accepted(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as bits, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as compat, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as config:
            bits.write("32\n"); bits.flush()
            compat.write("16\n"); compat.flush()
            config.write(
                "CONFIG_ARCH_MMAP_RND_BITS_MAX=32\n"
                "CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16\n"
            ); config.flush()
            self.assertEqual(
                scan_suboptimal_aslr_entropy(bits.name, compat.name, config.name),
                [],
            )

    def test_live_aslr_entropy_is_exercised_read_only(self):
        findings = scan_suboptimal_aslr_entropy()
        self.assertIsInstance(findings, list)
        for name, current, maximum in findings:
            self.assertIn(name, ("vm.mmap_rnd_bits", "vm.mmap_rnd_compat_bits"))
            self.assertLess(current, maximum)

    def test_aslr_entropy_finding_is_emitted_for_weak_value(self):
        weak = [("vm.mmap_rnd_bits", 28, 32)]
        with patch("hardaudit.scan_suboptimal_aslr_entropy", return_value=weak):
            findings = [f for f in audit_kernel().findings if "Entropie ASLR" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("28 bits", findings[0].detail)
        self.assertIn("32", findings[0].verify)

    def test_unlimited_recoverable_oopses_are_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as panic, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as limit:
            panic.write("0\n"); panic.flush()
            limit.write("0\n"); limit.flush()
            self.assertEqual(scan_unlimited_kernel_oopses(panic.name, limit.name), (0, 0))

        with patch("hardaudit.scan_unlimited_kernel_oopses", return_value=(0, 0)):
            findings = [f for f in audit_kernel().findings if "Oops kernel" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_representative_default_oops_limit_is_accepted(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as panic, \
                tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as limit:
            panic.write("0\n"); panic.flush()
            limit.write("10000\n"); limit.flush()
            self.assertIsNone(scan_unlimited_kernel_oopses(panic.name, limit.name))

    def test_live_oops_policy_is_exercised_read_only(self):
        result = scan_unlimited_kernel_oopses()
        self.assertIn(result, (None, (0, 0)))

    def test_magic_sysrq_reboot_bit_is_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysrq:
            sysrq.write("176\n"); sysrq.flush()
            self.assertEqual(
                scan_destructive_magic_sysrq(sysrq.name),
                (176, ["redemarrage/extinction"]),
            )

    def test_representative_recovery_only_sysrq_mask_is_accepted(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as sysrq:
            sysrq.write("0x30\n"); sysrq.flush()
            self.assertIsNone(scan_destructive_magic_sysrq(sysrq.name))

    def test_live_magic_sysrq_policy_is_exercised_read_only(self):
        result = scan_destructive_magic_sysrq()
        if result is not None:
            value, actions = result
            self.assertIsInstance(value, int)
            self.assertTrue(actions)

    def test_magic_sysrq_finding_is_emitted_for_destructive_mask(self):
        destructive = (192, ["signaux aux processus", "redemarrage/extinction"])
        with patch("hardaudit.scan_destructive_magic_sysrq", return_value=destructive):
            findings = [f for f in audit_kernel().findings if "Magic SysRq" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("192", findings[0].detail)

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


class PerfSamplingThrottleTests(unittest.TestCase):
    def _sysctl(self, value):
        sysctl = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        sysctl.write(f"{value}\n")
        sysctl.flush()
        return sysctl

    def test_disabled_perf_cpu_throttle_is_reported(self):
        with self._sysctl(0) as sysctl:
            self.assertEqual(hardaudit.scan_disabled_perf_cpu_throttle(sysctl.name), 0)

        with patch("hardaudit.scan_disabled_perf_cpu_throttle", return_value=0):
            findings = [f for f in audit_kernel().findings if "echantillonnage perf" in f.title]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("NMI", findings[0].detail)

    def test_representative_positive_perf_cpu_throttle_passes(self):
        with self._sysctl(25) as sysctl:
            self.assertIsNone(hardaudit.scan_disabled_perf_cpu_throttle(sysctl.name))

    def test_live_perf_cpu_throttle_is_read_without_modification(self):
        result = hardaudit.scan_disabled_perf_cpu_throttle()
        self.assertIn(result, (None, 0))


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

    @patch("hardaudit.scan_tcp_timewait_assassination", return_value=None)
    @patch("hardaudit.scan_unicast_ipv4_in_l2_multicast", return_value=[])
    @patch("hardaudit.scan_gratuitous_arp_updates", return_value=[])
    @patch("hardaudit.scan_locally_sourced_ipv4_interfaces", return_value=[])
    @patch("hardaudit.scan_unsafe_ipv4_redirect_senders", return_value=[])
    @patch("hardaudit.scan_unsafe_ipv4_redirects", return_value=[])
    @patch("hardaudit.scan_unsafe_ipv6_redirects", return_value=[])
    @patch("hardaudit.scan_unsafe_ipv6_source_routing", return_value=[])
    @patch("hardaudit.scan_unlogged_martian_interfaces", return_value=[])
    @patch("hardaudit.scan_unprotected_reverse_paths", return_value=[])
    @patch("hardaudit._capture")
    def test_allowed_port_stays_visible_without_penalty(
        self, capture, _rp, _martians, _ipv6_source, _ipv6_redirect, _accept, _send,
        _accept_local, _gratuitous_arp, _l2_multicast, _rfc1337
    ):
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


class SlabCacheMergingTests(unittest.TestCase):
    def _file(self, content):
        handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8")
        handle.write(content)
        handle.flush()
        return handle

    def test_default_slab_merging_is_reported(self):
        with self._file("CONFIG_SLAB_MERGE_DEFAULT=y\n") as config, \
                self._file("BOOT_IMAGE=/vmlinuz quiet\n") as cmdline:
            self.assertEqual(
                hardaudit.scan_slab_cache_merging(config.name, cmdline.name),
                True,
            )

        with patch("hardaudit.scan_slab_cache_merging", return_value=True):
            findings = [
                finding for finding in audit_kernel().findings
                if "caches slab" in finding.title.lower()
            ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertIn("heap", findings[0].detail)

    def test_representative_slab_nomerge_boot_policy_passes(self):
        with self._file("CONFIG_SLAB_MERGE_DEFAULT=y\n") as config, \
                self._file("quiet slab_nomerge audit=1\n") as cmdline:
            self.assertIsNone(
                hardaudit.scan_slab_cache_merging(config.name, cmdline.name)
            )

        with self._file("# CONFIG_SLAB_MERGE_DEFAULT is not set\n") as config, \
                self._file("quiet\n") as cmdline:
            self.assertIsNone(
                hardaudit.scan_slab_cache_merging(config.name, cmdline.name)
            )

    def test_live_slab_policy_is_exercised_read_only(self):
        self.assertIn(hardaudit.scan_slab_cache_merging(), (None, True))


if __name__ == "__main__":
    unittest.main()

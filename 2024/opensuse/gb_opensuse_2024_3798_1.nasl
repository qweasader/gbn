# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856632");
  script_version("2024-11-07T05:05:35+0000");
  script_cve_id("CVE-2021-46955", "CVE-2021-47291", "CVE-2021-47378", "CVE-2021-47383", "CVE-2021-47402", "CVE-2021-47598", "CVE-2022-48651", "CVE-2023-1829", "CVE-2023-52752", "CVE-2023-6531", "CVE-2023-6546", "CVE-2024-23307", "CVE-2024-26610", "CVE-2024-26828", "CVE-2024-26852", "CVE-2024-26923", "CVE-2024-27398", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35864", "CVE-2024-35950", "CVE-2024-36964", "CVE-2024-41059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-31 20:38:12 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-10-31 05:00:31 +0000 (Thu, 31 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 42 for SLE 15 SP3) (SUSE-SU-2024:3798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3798-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HFYLKQ636KZTC2VVITC5E7NJ7IFE4RRA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 42 for SLE 15 SP3)'
  package(s) announced via the SUSE-SU-2024:3798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.3.18-150300_59_153 fixes several issues.

  The following security issues were fixed:

  * CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init()
      (bsc#1227471).

  * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225819).

  * CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()
      (bsc#1225311).

  * CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()
      (bsc#1225309).

  * CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()
      (bsc#1225312).

  * CVE-2021-47291: ipv6: fix another slab-out-of-bounds in
      fib6_nh_flush_exceptions (bsc#1227651).

  * CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228573).

  * CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000
      (bsc#1226325).

  * CVE-2021-47402: Protect fl_walk() with rcu (bsc#1225301)

  * CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free
      (bsc#1225202).

  * CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout
      (bsc#1225013).

  * CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex
      (bsc#1225310).

  * CVE-2021-47383: Fixed out-of-bound vmalloc access in imageblit
      (bsc#1225211).

  * CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in
      __unix_gc() (bsc#1223683).

  * CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223363).

  * CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when
      fragmenting IPv4 packets (bsc#1220537).

  * CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86
      and ARM md, raid, raid5 modules (bsc#1220145).

  * CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify()
      (bsc#1223059).

  * CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221302).

  * CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset
      skb->mac_header (bsc#1223514).

  * CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via
      the GSMIOC_SETCONF ioctl that could lead to local privilege escalation
      (bsc#1222685).

  * CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix
      garbage collector's deletion of SKB races with unix_stream_read_generic()on
      the socket that the SKB is queued on (bsc#1218487).

  * CVE-2023-1829: Fixed a use-after-free vulnerability in the control index
      filter (tcindex) (bsc#1210619).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 42 for SLE 15 SP3)' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.3.18-150300.59.153-default-debuginfo-9", rpm:"kernel-livepatch-5.3.18-150300.59.153-default-debuginfo-9~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.3.18-150300.59.153-default-9", rpm:"kernel-livepatch-5.3.18-150300.59.153-default-9~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP3.Update.42-debugsource-9", rpm:"kernel-livepatch-SLE15-SP3.Update.42-debugsource-9~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.3.18-150300.59.153-preempt-debuginfo-9", rpm:"kernel-livepatch-5.3.18-150300.59.153-preempt-debuginfo-9~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.3.18-150300.59.153-preempt-9", rpm:"kernel-livepatch-5.3.18-150300.59.153-preempt-9~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

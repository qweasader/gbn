# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856651");
  script_version("2024-11-07T05:05:35+0000");
  script_cve_id("CVE-2021-47598", "CVE-2023-52752", "CVE-2023-52846", "CVE-2024-26828", "CVE-2024-26852", "CVE-2024-26923", "CVE-2024-26930", "CVE-2024-27398", "CVE-2024-35817", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35863", "CVE-2024-35864", "CVE-2024-35867", "CVE-2024-35905", "CVE-2024-35950", "CVE-2024-36899", "CVE-2024-36964", "CVE-2024-40954", "CVE-2024-41059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-28 19:43:58 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-10-31 05:03:09 +0000 (Thu, 31 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 26 for SLE 15 SP4) (SUSE-SU-2024:3806-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3806-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I22FOLEFZIBTJBTIPHH5GXPKMIXVDSDI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 26 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2024:3806-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_24_119 fixes several issues.

  The following security issues were fixed:

  * CVE-2024-35905: Fixed int overflow for stack access size (bsc#1226327).

  * CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init()
      (bsc#1227471).

  * CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break()
      (bsc#1225011).

  * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225819).

  * CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()
      (bsc#1225311).

  * CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1225012).

  * CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()
      (bsc#1225309).

  * Intermittent nfs mount failures (may be due to SUNRPC over UDP)
      (bsc#1231353)

  * CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()
      (bsc#1225312).

  * CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify
      (bsc#1225739).

  * CVE-2024-40954: net: do not leave a dangling sk pointer, when socket
      creation fails (bsc#1227808)

  * CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228573).

  * CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000
      (bsc#1226325).

  * CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame()
      (bsc#1225099).

  * CVE-2024-35817: Set gtt bound flag in amdgpu_ttm_gart_bind (bsc#1225313).

  * CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout
      (bsc#1225013).

  * CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex
      (bsc#1225310).

  * CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in
      __unix_gc() (bsc#1223683).

  * CVE-2024-26930: Fixed double free of the ha->vp_map pointer (bsc#1223681).

  * CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223363).

  * CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify()
      (bsc#1223059).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 26 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.14.21-150400.24.119-default-debuginfo-7", rpm:"kernel-livepatch-5.14.21-150400.24.119-default-debuginfo-7~150400.9.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5.14.21-150400.24.119-default-7", rpm:"kernel-livepatch-5.14.21-150400.24.119-default-7~150400.9.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4.Update.26-debugsource-7", rpm:"kernel-livepatch-SLE15-SP4.Update.26-debugsource-7~150400.9.6.1", rls:"openSUSELeap15.4"))) {
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

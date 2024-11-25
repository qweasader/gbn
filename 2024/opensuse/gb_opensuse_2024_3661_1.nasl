# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856602");
  script_version("2024-10-25T05:05:38+0000");
  script_cve_id("CVE-2021-47291", "CVE-2024-26923", "CVE-2024-35861", "CVE-2024-35950", "CVE-2024-36964", "CVE-2024-41059");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-10 17:25:18 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-10-17 04:03:38 +0000 (Thu, 17 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 45 for SLE 15 SP3) (SUSE-SU-2024:3661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3661-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LI6Q2FNQZMLDTI4OK3SIOBF2CXJW5I56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 45 for SLE 15 SP3)'
  package(s) announced via the SUSE-SU-2024:3661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.3.18-150300_59_164 fixes several issues.

  The following security issues were fixed:

  * CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()
      (bsc#1225312).

  * CVE-2021-47291: ipv6: fix another slab-out-of-bounds in
      fib6_nh_flush_exceptions (bsc#1227651).

  * CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228573).

  * CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000
      (bsc#1226325).

  * CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in
      __unix_gc() (bsc#1223683).

  * CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex
      (bsc#1225310).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 45 for SLE 15 SP3)' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_164-default-debuginfo-3", rpm:"kernel-livepatch-5_3_18-150300_59_164-default-debuginfo-3~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP3_Update_45-debugsource-3", rpm:"kernel-livepatch-SLE15-SP3_Update_45-debugsource-3~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_164-default-3", rpm:"kernel-livepatch-5_3_18-150300_59_164-default-3~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_164-preempt-debuginfo-3", rpm:"kernel-livepatch-5_3_18-150300_59_164-preempt-debuginfo-3~150300.7.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_3_18-150300_59_164-preempt-3", rpm:"kernel-livepatch-5_3_18-150300_59_164-preempt-3~150300.7.6.1", rls:"openSUSELeap15.3"))) {
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
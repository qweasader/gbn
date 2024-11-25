# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856594");
  script_version("2024-10-25T05:05:38+0000");
  script_cve_id("CVE-2023-52846", "CVE-2024-35817", "CVE-2024-35861", "CVE-2024-36899", "CVE-2024-36964", "CVE-2024-40954");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-28 19:43:58 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-10-17 04:02:47 +0000 (Thu, 17 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 0 for SLE 15 SP6) (SUSE-SU-2024:3666-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3666-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EUYMTMU2SZQY2ZOCLHCYEZ2A2LJUYBHS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 0 for SLE 15 SP6)'
  package(s) announced via the SUSE-SU-2024:3666-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 6.4.0-150600_21 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame()
      (bsc#1225099).

  * CVE-2024-35817: Set gtt bound flag in amdgpu_ttm_gart_bind (bsc#1225313).

  * CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()
      (bsc#1225312).

  * CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify
      (bsc#1225739).

  * CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000
      (bsc#1226325).

  * CVE-2024-40954: net: do not leave a dangling sk pointer, when socket
      creation fails (bsc#1227808)");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 0 for SLE 15 SP6)' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_4_0-150600_21-default-5", rpm:"kernel-livepatch-6_4_0-150600_21-default-5~150600.1.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_4_0-150600_21-default-debuginfo-5", rpm:"kernel-livepatch-6_4_0-150600_21-default-debuginfo-5~150600.1.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP6_Update_0-debugsource-5", rpm:"kernel-livepatch-SLE15-SP6_Update_0-debugsource-5~150600.1.1", rls:"openSUSELeap15.6"))) {
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
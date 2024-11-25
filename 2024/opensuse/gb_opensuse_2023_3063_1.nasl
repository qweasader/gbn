# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833261");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-2002", "CVE-2023-2235", "CVE-2023-35788");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:43:57 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel RT (Live Patch 2 for SLE 15 SP4) (SUSE-SU-2023:3063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3063-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PIDMWS7TGZ75WYKEK3CIHJ2LJ2EPCKD2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel RT (Live Patch 2 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2023:3063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_15_8 fixes several issues.

  The following security issues were fixed:

  * CVE-2023-35788: Fixed an out-of-bounds write in the flower classifier code
      via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets in fl_set_geneve_opt in
      net/sched/cls_flower.c (bsc#1212509).

  * CVE-2023-2235: Fixed an use-after-free in the Performance Events system can
      be exploited to achieve local privilege escalation (bsc#1210987).

  * CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized
      execution of management commands, compromising the confidentiality,
      integrity, and availability of Bluetooth communication (bsc#1210566).

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel RT (Live Patch 2 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-12", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-12", rpm:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-12", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-12~150400.2.2##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-6", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-debuginfo-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-9", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-12", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-9", rpm:"kernel-livepatch-SLE15-SP4_Update_5-debugsource-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-6", rpm:"kernel-livepatch-SLE15-SP4_Update_8-debugsource-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-12", rpm:"kernel-livepatch-SLE15-SP4_Update_3-debugsource-12~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_46-default-6", rpm:"kernel-livepatch-5_14_21-150400_24_46-default-6~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-9", rpm:"kernel-livepatch-5_14_21-150400_24_33-default-debuginfo-9~150400.2.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-12", rpm:"kernel-livepatch-5_14_21-150400_24_21-default-debuginfo-12~150400.2.2##", rls:"openSUSELeap15.4"))) {
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
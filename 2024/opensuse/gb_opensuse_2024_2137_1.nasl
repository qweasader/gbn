# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856268");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2018-20797", "CVE-2019-10723", "CVE-2019-9199");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-27 15:10:32 +0000 (Wed, 27 Feb 2019)");
  script_tag(name:"creation_date", value:"2024-06-29 04:07:44 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for podofo (SUSE-SU-2024:2137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2137-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YUGKYVVXAYFHQRSHO4PIUSZRC44OKZND");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podofo'
  package(s) announced via the SUSE-SU-2024:2137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podofo fixes the following issues:

  * CVE-2019-9199: Fixed a NULL pointer dereference in podofoimpose
      (bsc#1127855)

  * CVE-2018-20797: Fixed an excessive memory allocation in PoDoFo:podofo_calloc
      (bsc#1127514)

  * CVE-2019-10723: Fixed a memory leak in PdfPagesTreeCache (bsc#1131544)

  ##");

  script_tag(name:"affected", value:"'podofo' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~150300.3.9.1", rls:"openSUSELeap15.3"))) {
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
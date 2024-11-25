# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856449");
  script_version("2024-09-12T07:59:53+0000");
  script_cve_id("CVE-2024-21131", "CVE-2024-21138", "CVE-2024-21140", "CVE-2024-21144", "CVE-2024-21145", "CVE-2024-21147");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 23:15:16 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-09-07 04:01:05 +0000 (Sat, 07 Sep 2024)");
  script_name("openSUSE: Security Advisory for java (SUSE-SU-2024:3140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3140-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HWVUZ3UEMLM5HBF7VKWLBJCKDM2KXJSZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the SUSE-SU-2024:3140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openj9 fixes the following issues:

  * Update to OpenJDK 8u422 build 05 with OpenJ9 0.46.0 virtual machine

  * CVE-2024-21147: Fixed an array index overflow in RangeCheckElimination.
      (bsc#1228052)

  * CVE-2024-21145: Fixed an out-of-bounds access in 2D image handling.
      (bsc#1228051)

  * CVE-2024-21140: Fixed a range check elimination pre-loop limit overflow.
      (bsc#1228048)

  * CVE-2024-21144: Pack200 increase loading time due to improper header
      validation. (bsc#1228050)

  * CVE-2024-21138: Fixed an issue where excessive symbol length can lead to
      infinite loop. (bsc#1228047)

  * CVE-2024-21131: Fixed a potential UTF8 size overflow. (bsc#1228046)

  ##");

  script_tag(name:"affected", value:"'java' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless-debuginfo", rpm:"java-1_8_0-openj9-headless-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-accessibility", rpm:"java-1_8_0-openj9-accessibility~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo", rpm:"java-1_8_0-openj9-demo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debuginfo", rpm:"java-1_8_0-openj9-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel", rpm:"java-1_8_0-openj9-devel~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless", rpm:"java-1_8_0-openj9-headless~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-src", rpm:"java-1_8_0-openj9-src~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel-debuginfo", rpm:"java-1_8_0-openj9-devel-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debugsource", rpm:"java-1_8_0-openj9-debugsource~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo-debuginfo", rpm:"java-1_8_0-openj9-demo-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9", rpm:"java-1_8_0-openj9~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-javadoc", rpm:"java-1_8_0-openj9-javadoc~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless-debuginfo", rpm:"java-1_8_0-openj9-headless-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-accessibility", rpm:"java-1_8_0-openj9-accessibility~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo", rpm:"java-1_8_0-openj9-demo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debuginfo", rpm:"java-1_8_0-openj9-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel", rpm:"java-1_8_0-openj9-devel~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless", rpm:"java-1_8_0-openj9-headless~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-src", rpm:"java-1_8_0-openj9-src~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel-debuginfo", rpm:"java-1_8_0-openj9-devel-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-debugsource", rpm:"java-1_8_0-openj9-debugsource~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo-debuginfo", rpm:"java-1_8_0-openj9-demo-debuginfo~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9", rpm:"java-1_8_0-openj9~1.8.0.422~150200.3.48.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-javadoc", rpm:"java-1_8_0-openj9-javadoc~1.8.0.422~150200.3.48.2##", rls:"openSUSELeap15.5"))) {
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
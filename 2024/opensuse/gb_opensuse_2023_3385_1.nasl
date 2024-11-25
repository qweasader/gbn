# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833556");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-33546");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 18:49:27 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:06:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for janino (SUSE-SU-2023:3385-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3385-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3T46NGR75LTPD7RGUU4LH4E73ZPTH6PW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'janino'
  package(s) announced via the SUSE-SU-2023:3385-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for janino fixes the following issues:

  janino was upgraded to version 3.1.10:

  * CVE-2023-33546: Fixed DoS due to missing error handling (bsc#1211923).

  ##");

  script_tag(name:"affected", value:"'janino' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler", rpm:"commons-compiler~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino", rpm:"janino~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino-javadoc", rpm:"janino-javadoc~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler", rpm:"commons-compiler~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino", rpm:"janino~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino-javadoc", rpm:"janino-javadoc~3.1.10~150200.3.7.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"janino-javadoc", rpm:"janino-javadoc~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler", rpm:"commons-compiler~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino", rpm:"janino~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler-jdk", rpm:"commons-compiler-jdk~3.1.10~150200.3.7.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino-javadoc", rpm:"janino-javadoc~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler", rpm:"commons-compiler~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"janino", rpm:"janino~3.1.10~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"commons-compiler-jdk", rpm:"commons-compiler-jdk~3.1.10~150200.3.7.1##", rls:"openSUSELeap15.5"))) {
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
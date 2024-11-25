# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833617");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2018-21232");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-07 20:13:00 +0000 (Thu, 07 May 2020)");
  script_tag(name:"creation_date", value:"2024-03-04 07:35:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for re2c (SUSE-SU-2023:3353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3353-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JTH243S57VZQUFZMFFQZVG4LEG2VCTHV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 're2c'
  package(s) announced via the SUSE-SU-2023:3353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for re2c fixes the following issues:

  * CVE-2018-21232: Fixed excess stack consumption due to uncontrolled recursion
      in find_fixed_tags (bsc#1170890).

  ##");

  script_tag(name:"affected", value:"'re2c' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"re2c-debugsource", rpm:"re2c-debugsource~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debuginfo", rpm:"re2c-debuginfo~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c", rpm:"re2c~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debugsource", rpm:"re2c-debugsource~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debuginfo", rpm:"re2c-debuginfo~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c", rpm:"re2c~1.0.3~150000.3.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"re2c-debugsource", rpm:"re2c-debugsource~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debuginfo", rpm:"re2c-debuginfo~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c", rpm:"re2c~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debugsource", rpm:"re2c-debugsource~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c-debuginfo", rpm:"re2c-debuginfo~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2c", rpm:"re2c~1.0.3~150000.3.3.1", rls:"openSUSELeap15.5"))) {
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
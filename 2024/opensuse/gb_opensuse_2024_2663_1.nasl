# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856353");
  script_version("2024-08-28T05:05:33+0000");
  script_cve_id("CVE-2024-40897");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 13:52:53 +0000 (Tue, 27 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:46 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for orc (SUSE-SU-2024:2663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2663-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U3ARX2RYP6N2TA6CKMTHGAOZPYWUZCCF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'orc'
  package(s) announced via the SUSE-SU-2024:2663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for orc fixes the following issues:

  * CVE-2024-40897: Fixed stack-based buffer overflow in the orc compiler when
      formatting error messages for certain input files (bsc#1228184)

  ##");

  script_tag(name:"affected", value:"'orc' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"orc-debuginfo", rpm:"orc-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0", rpm:"liborc-0_4-0~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc-doc", rpm:"orc-doc~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc", rpm:"orc~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-debuginfo", rpm:"liborc-0_4-0-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc-debugsource", rpm:"orc-debugsource~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-32bit", rpm:"liborc-0_4-0-32bit~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-32bit-debuginfo", rpm:"liborc-0_4-0-32bit-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"orc-debuginfo", rpm:"orc-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0", rpm:"liborc-0_4-0~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc-doc", rpm:"orc-doc~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc", rpm:"orc~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-debuginfo", rpm:"liborc-0_4-0-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"orc-debugsource", rpm:"orc-debugsource~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-32bit", rpm:"liborc-0_4-0-32bit~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liborc-0_4-0-32bit-debuginfo", rpm:"liborc-0_4-0-32bit-debuginfo~0.4.28~150000.3.6.1", rls:"openSUSELeap15.5"))) {
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
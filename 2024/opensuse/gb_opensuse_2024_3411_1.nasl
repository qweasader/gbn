# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856514");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-26 04:01:53 +0000 (Thu, 26 Sep 2024)");
  script_name("openSUSE: Security Advisory for python39 (SUSE-SU-2024:3411-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3411-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QNXFOIXBCGZTXD6BKYGBL3VDWS6RK6AB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39'
  package(s) announced via the SUSE-SU-2024:3411-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

  * Update to 3.9.20:

  * CVE-2024-6232: excessive backtracking when parsing tarfile headers leads to
      ReDoS. (bsc#1230227)

  * CVE-2024-7592: quadratic algorithm used when parsing cookies leads to
      excessive resource consumption. (bsc#1229596)

  * CVE-2024-8088: lack of name validation when extracting a zip archive leads
      to infinite loops. (bsc#1229704)");

  script_tag(name:"affected", value:"'python39' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc-devhelp", rpm:"python39-doc-devhelp~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite-debuginfo", rpm:"python39-testsuite-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite", rpm:"python39-testsuite~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc", rpm:"python39-doc~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit", rpm:"python39-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit-debuginfo", rpm:"libpython3_9-1_0-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit-debuginfo", rpm:"python39-base-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit", rpm:"libpython3_9-1_0-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit-debuginfo", rpm:"python39-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit", rpm:"python39-base-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc-devhelp", rpm:"python39-doc-devhelp~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite-debuginfo", rpm:"python39-testsuite-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite", rpm:"python39-testsuite~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc", rpm:"python39-doc~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit", rpm:"python39-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit-debuginfo", rpm:"libpython3_9-1_0-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit-debuginfo", rpm:"python39-base-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit", rpm:"libpython3_9-1_0-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit-debuginfo", rpm:"python39-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit", rpm:"python39-base-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc-devhelp", rpm:"python39-doc-devhelp~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite-debuginfo", rpm:"python39-testsuite-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite", rpm:"python39-testsuite~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc", rpm:"python39-doc~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit", rpm:"python39-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit-debuginfo", rpm:"libpython3_9-1_0-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit-debuginfo", rpm:"python39-base-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit", rpm:"libpython3_9-1_0-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit-debuginfo", rpm:"python39-32bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit", rpm:"python39-base-32bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-64bit", rpm:"python39-64bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-64bit-debuginfo", rpm:"libpython3_9-1_0-64bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-64bit-debuginfo", rpm:"python39-base-64bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-64bit", rpm:"python39-base-64bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-64bit", rpm:"libpython3_9-1_0-64bit~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-64bit-debuginfo", rpm:"python39-64bit-debuginfo~3.9.20~150300.4.52.1", rls:"openSUSELeap15.3"))) {
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
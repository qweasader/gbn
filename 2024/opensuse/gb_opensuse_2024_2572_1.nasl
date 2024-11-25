# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856327");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2024-0397", "CVE-2024-4030", "CVE-2024-4032");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:54 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for python312 (SUSE-SU-2024:2572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2572-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HXF7OI6CNM6JDY342A7VXRMZRG6D3WZF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python312'
  package(s) announced via the SUSE-SU-2024:2572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python312 fixes the following issues:

  * CVE-2024-4032: Corrected information about public and private IPv4 and IPv6
      address ranges (bsc#1226448).");

  script_tag(name:"affected", value:"'python312' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python312-dbm-debuginfo", rpm:"python312-dbm-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0-debuginfo", rpm:"libpython3.12-1.0-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base", rpm:"python312-base~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-idle", rpm:"python312-idle~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tools", rpm:"python312-tools~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-dbm", rpm:"python312-dbm~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-debuginfo", rpm:"python312-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312", rpm:"python312~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-devel", rpm:"python312-devel~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-testsuite", rpm:"python312-testsuite~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0", rpm:"libpython3.12-1.0~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-testsuite-debuginfo", rpm:"python312-testsuite-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-debugsource", rpm:"python312-debugsource~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-doc", rpm:"python312-doc~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tk", rpm:"python312-tk~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-curses", rpm:"python312-curses~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-core-debugsource", rpm:"python312-core-debugsource~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-curses-debuginfo", rpm:"python312-curses-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-debuginfo", rpm:"python312-base-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-doc-devhelp", rpm:"python312-doc-devhelp~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tk-debuginfo", rpm:"python312-tk-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0-32bit", rpm:"libpython3.12-1.0-32bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-32bit", rpm:"python312-32bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-32bit-debuginfo", rpm:"python312-32bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-32bit-debuginfo", rpm:"python312-base-32bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-32bit", rpm:"python312-base-32bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0-32bit-debuginfo", rpm:"libpython3.12-1.0-32bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-64bit-debuginfo", rpm:"python312-base-64bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0-64bit-debuginfo", rpm:"libpython3.12-1.0-64bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-64bit", rpm:"python312-base-64bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-64bit", rpm:"python312-64bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-64bit-debuginfo", rpm:"python312-64bit-debuginfo~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.12-1.0-64bit", rpm:"libpython3.12-1.0-64bit~3.12.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3357.1");
  script_cve_id("CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2024-09-23 04:28:17 +0000 (Mon, 23 Sep 2024)");
  script_version("2024-09-23T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-23 05:05:44 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3357-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243357-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310' package(s) announced via the SUSE-SU-2024:3357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:

Update to version 3.10.15 CVE-2024-8088: Fixed denial of service in zipfile. (bsc#1229704)
CVE-2024-7592: Fixed uncontrolled CPU resource consumption when in http.cookies module. (bsc#1229596)
CVE-2024-6232: Fixed ReDos via excessive backtracking while parsing header values. (bsc#1230227)");

  script_tag(name:"affected", value:"'python310' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-debuginfo", rpm:"libpython3_10-1_0-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-debuginfo", rpm:"python310-base-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-core-debugsource", rpm:"python310-core-debugsource~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses-debuginfo", rpm:"python310-curses-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm-debuginfo", rpm:"python310-dbm-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debuginfo", rpm:"python310-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-debugsource", rpm:"python310-debugsource~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk-debuginfo", rpm:"python310-tk-debuginfo~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.15~150400.4.57.1", rls:"SLES15.0SP4"))) {
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

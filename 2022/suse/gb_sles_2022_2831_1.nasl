# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2831.1");
  script_cve_id("CVE-2020-29651");
  script_tag(name:"creation_date", value:"2022-08-18 04:49:30 +0000 (Thu, 18 Aug 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 03:15:00 +0000 (Tue, 05 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2831-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222831-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws-efs-utils, python-ansi2html, python-coverage, python-oniconfig, python-py, python-pytest-html, python-pytest-metadata, python-pytest-rerunfailures, python-unittest-mixins' package(s) announced via the SUSE-SU-2022:2831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aws-efs-utils, python-ansi2html, python-py,
python-pytest-html, python-pytest-metadata, python-pytest-rerunfailures fixes the following issues:

Update in SLE-15 (bsc#1196696, bsc#1195916, jsc#SLE-23972)

Remove redundant python3 dependency from Requires

Update regular expression to fix python shebang

Style is enforced upstream and triggers unnecessary build version
 requirements

Allow specifying fs_id in cloudwatch log group name

Includes fix for stunnel path

Added hardening to systemd service(s).

Raise minimal pytest version

Fix typo in the ansi2html Requires

Cleanup with spec-cleaner

Make sure the tests are really executed

Remove useless devel dependency

Multiprocessing support in Python 3.8 was broken, but is now fixed

Bumpy the URL to point to github rather than to docs");

  script_tag(name:"affected", value:"'aws-efs-utils, python-ansi2html, python-coverage, python-oniconfig, python-py, python-pytest-html, python-pytest-metadata, python-pytest-rerunfailures, python-unittest-mixins' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Module for Public Cloud 15-SP1, SUSE Linux Enterprise Module for Public Cloud 15-SP2, SUSE Linux Enterprise Module for Public Cloud 15-SP3, SUSE Linux Enterprise Module for Public Cloud 15-SP4, SUSE Linux Enterprise Module for Python2 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-apipkg", rpm:"python3-apipkg~1.4~150000.3.2.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-iniconfig", rpm:"python3-iniconfig~1.1.1~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-py", rpm:"python3-py~1.10.0~150000.5.9.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-coverage-debuginfo", rpm:"python-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-coverage-debugsource", rpm:"python-coverage-debugsource~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-coverage", rpm:"python3-coverage~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-coverage-debuginfo", rpm:"python3-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-atomicwrites", rpm:"python2-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-coverage", rpm:"python2-coverage~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-coverage-debuginfo", rpm:"python2-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-atomicwrites", rpm:"python3-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-apipkg", rpm:"python2-apipkg~1.4~150000.3.2.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-iniconfig", rpm:"python2-iniconfig~1.1.1~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-py", rpm:"python2-py~1.10.0~150000.5.9.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python3-apipkg", rpm:"python3-apipkg~1.4~150000.3.2.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-iniconfig", rpm:"python3-iniconfig~1.1.1~150000.1.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-py", rpm:"python3-py~1.10.0~150000.5.9.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-coverage-debuginfo", rpm:"python-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-coverage-debugsource", rpm:"python-coverage-debugsource~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-coverage", rpm:"python3-coverage~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-coverage-debuginfo", rpm:"python3-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-atomicwrites", rpm:"python2-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-coverage", rpm:"python2-coverage~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-coverage-debuginfo", rpm:"python2-coverage-debuginfo~4.5.4~150000.3.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-atomicwrites", rpm:"python3-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python3-atomicwrites", rpm:"python3-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python3-atomicwrites", rpm:"python3-atomicwrites~1.1.5~150000.3.2.1", rls:"SLES15.0SP2"))) {
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

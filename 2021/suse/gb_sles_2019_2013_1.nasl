# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2013.1");
  script_cve_id("CVE-2019-12900");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-21 15:39:26 +0000 (Fri, 21 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2013-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192013-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bzip2' package(s) announced via the SUSE-SU-2019:2013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bzip2 fixes the following issues:
Fixed a regression with the fix for CVE-2019-12900, which caused
 incompatibilities with files that used many selectors (bsc#1139083).");

  script_tag(name:"affected", value:"'bzip2' package(s) on SUSE CaaS Platform 3.0, SUSE Enterprise Storage 4, SUSE Enterprise Storage 5, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debuginfo", rpm:"bzip2-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debugsource", rpm:"bzip2-debugsource~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-32bit", rpm:"libbz2-1-32bit~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo", rpm:"libbz2-1-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo-32bit", rpm:"libbz2-1-debuginfo-32bit~1.0.6~30.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debuginfo", rpm:"bzip2-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debugsource", rpm:"bzip2-debugsource~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-32bit", rpm:"libbz2-1-32bit~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo", rpm:"libbz2-1-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo-32bit", rpm:"libbz2-1-debuginfo-32bit~1.0.6~30.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debuginfo", rpm:"bzip2-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debugsource", rpm:"bzip2-debugsource~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-32bit", rpm:"libbz2-1-32bit~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo", rpm:"libbz2-1-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo-32bit", rpm:"libbz2-1-debuginfo-32bit~1.0.6~30.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debuginfo", rpm:"bzip2-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debugsource", rpm:"bzip2-debugsource~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-32bit", rpm:"libbz2-1-32bit~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo", rpm:"libbz2-1-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo-32bit", rpm:"libbz2-1-debuginfo-32bit~1.0.6~30.8.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"bzip2", rpm:"bzip2~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debuginfo", rpm:"bzip2-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-debugsource", rpm:"bzip2-debugsource~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bzip2-doc", rpm:"bzip2-doc~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1", rpm:"libbz2-1~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-32bit", rpm:"libbz2-1-32bit~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo", rpm:"libbz2-1-debuginfo~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbz2-1-debuginfo-32bit", rpm:"libbz2-1-debuginfo-32bit~1.0.6~30.8.1", rls:"SLES12.0SP5"))) {
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

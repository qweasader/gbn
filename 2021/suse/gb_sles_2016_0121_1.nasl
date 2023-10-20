# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0121.1");
  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4895", "CVE-2015-4913");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160121-1/");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10022-release-notes/");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10021-release-notes/");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10022-changelog/");
  script_xref(name:"URL", value:"https://kb.askmonty.org/en/mariadb-10021-changelog/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2016:0121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MariaDB has been updated to version 10.0.22, which brings fixes for many security issues and other improvements.
The following CVEs have been fixed:
- 10.0.22: CVE-2015-4802, CVE-2015-4807, CVE-2015-4815, CVE-2015-4826,
 CVE-2015-4830, CVE-2015-4836, CVE-2015-4858, CVE-2015-4861,
 CVE-2015-4870, CVE-2015-4913, CVE-2015-4792
- 10.0.21: CVE-2015-4816, CVE-2015-4819, CVE-2015-4879, CVE-2015-4895 The following non-security issues have been fixed:
- Fix rc.mysql-multi script to properly start instances after restart.
 (bsc#934401)
- Fix rc.mysql-multi script to restart after crash. (bsc#937258)
For a comprehensive list of changes refer to the upstream Release Notes and Change Log documents:
- [link moved to references]
- [link moved to references]
- [link moved to references]
- [link moved to references]");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18", rpm:"libmysqlclient18~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-32bit", rpm:"libmysqlclient18-32bit~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo", rpm:"libmysqlclient18-debuginfo~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient18-debuginfo-32bit", rpm:"libmysqlclient18-debuginfo-32bit~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client-debuginfo", rpm:"mariadb-client-debuginfo~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debuginfo", rpm:"mariadb-debuginfo~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-debugsource", rpm:"mariadb-debugsource~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.0.22~20.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools-debuginfo", rpm:"mariadb-tools-debuginfo~10.0.22~20.3.1", rls:"SLES12.0"))) {
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

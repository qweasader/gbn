# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0482.1");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0482-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160482-1/");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-9-4-5.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql94' package(s) announced via the SUSE-SU-2016:0482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of postgresql94 to 9.4.5 fixes the following issues:
* CVE-2015-5289: json or jsonb input values constructed from arbitrary
 user input could have crashed the PostgreSQL server and caused a denial
 of service (bsc#949670)
* CVE-2015-5288: crypt() (pgCrypto extension) couldi potentially be
 exploited to read a few additional bytes of memory (bsc#949669)
Also contains all changes and bugfixes in the upstream 9.4.5 release:
[link moved to references]");

  script_tag(name:"affected", value:"'postgresql94' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for VMWare 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP4, SUSE Manager 2.1.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.5~0.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94", rpm:"postgresql94~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-contrib", rpm:"postgresql94-contrib~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-docs", rpm:"postgresql94-docs~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql94-server", rpm:"postgresql94-server~9.4.5~0.8.3", rls:"SLES11.0SP4"))) {
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

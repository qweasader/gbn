# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0586.1");
  script_cve_id("CVE-2020-1720");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-27 17:39:45 +0000 (Fri, 27 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0586-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200586-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql96' package(s) announced via the SUSE-SU-2020:0586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql96 fixes the following issues:

PostgreSQL was updated to version 9.6.17.

Security issue fixed:
CVE-2020-1720: Fixed a missing authorization check in the ALTER ...
 DEPENDS ON extension (bsc#1163985).");

  script_tag(name:"affected", value:"'postgresql96' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl", rpm:"postgresql96-plperl~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl-debuginfo", rpm:"postgresql96-plperl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython", rpm:"postgresql96-plpython~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython-debuginfo", rpm:"postgresql96-plpython-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl", rpm:"postgresql96-pltcl~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl-debuginfo", rpm:"postgresql96-pltcl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl", rpm:"postgresql96-plperl~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl-debuginfo", rpm:"postgresql96-plperl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython", rpm:"postgresql96-plpython~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython-debuginfo", rpm:"postgresql96-plpython-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl", rpm:"postgresql96-pltcl~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl-debuginfo", rpm:"postgresql96-pltcl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql96", rpm:"postgresql96~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib", rpm:"postgresql96-contrib~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-contrib-debuginfo", rpm:"postgresql96-contrib-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debuginfo", rpm:"postgresql96-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-debugsource", rpm:"postgresql96-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-docs", rpm:"postgresql96-docs~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-libs-debugsource", rpm:"postgresql96-libs-debugsource~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl", rpm:"postgresql96-plperl~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plperl-debuginfo", rpm:"postgresql96-plperl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython", rpm:"postgresql96-plpython~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-plpython-debuginfo", rpm:"postgresql96-plpython-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl", rpm:"postgresql96-pltcl~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-pltcl-debuginfo", rpm:"postgresql96-pltcl-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server", rpm:"postgresql96-server~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql96-server-debuginfo", rpm:"postgresql96-server-debuginfo~9.6.17~3.33.1", rls:"SLES12.0SP3"))) {
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

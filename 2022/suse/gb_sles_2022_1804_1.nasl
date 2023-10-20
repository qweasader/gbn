# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1804.1");
  script_cve_id("CVE-2022-1552");
  script_tag(name:"creation_date", value:"2022-05-24 04:27:49 +0000 (Tue, 24 May 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 20:04:00 +0000 (Wed, 07 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1804-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221804-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql10' package(s) announced via the SUSE-SU-2022:1804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql10 fixes the following issues:

CVE-2022-1552: Confine additional operations within 'security restricted
 operation' sandboxes (bsc#1199475).");

  script_tag(name:"affected", value:"'postgresql10' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.21~4.28.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.21~4.28.3", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.21~4.28.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.21~4.28.3", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.21~4.28.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.21~4.28.3", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"postgresql10", rpm:"postgresql10~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib", rpm:"postgresql10-contrib~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-contrib-debuginfo", rpm:"postgresql10-contrib-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debuginfo", rpm:"postgresql10-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-debugsource", rpm:"postgresql10-debugsource~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-docs", rpm:"postgresql10-docs~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl", rpm:"postgresql10-plperl~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plperl-debuginfo", rpm:"postgresql10-plperl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython", rpm:"postgresql10-plpython~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-plpython-debuginfo", rpm:"postgresql10-plpython-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl", rpm:"postgresql10-pltcl~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-pltcl-debuginfo", rpm:"postgresql10-pltcl-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server", rpm:"postgresql10-server~10.21~4.28.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql10-server-debuginfo", rpm:"postgresql10-server-debuginfo~10.21~4.28.3", rls:"SLES12.0SP5"))) {
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

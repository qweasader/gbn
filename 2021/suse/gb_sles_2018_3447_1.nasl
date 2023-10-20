# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3447.1");
  script_cve_id("CVE-2018-18065");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 18:15:00 +0000 (Wed, 16 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3447-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183447-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SUSE-SU-2018:3447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-snmp fixes the following issues:

Security issues fixed:
CVE-2018-18065: _set_key in agent/helpers/table_container.c had a NULL
 Pointer Exception bug that can be used by an authenticated attacker to
 remotely cause the instance to crash via a crafted UDP packet, resulting
 in Denial of Service. (bsc#1111122)

Non-security issues fixed:
swintst_rpm: Protect against unspecified Group name (bsc#1102775)

Add tsm and tlstm MIBs and the USM security module. (bsc#1081164)

Fix agentx freezing on timeout (bsc#1027353)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on SUSE CaaS Platform 3.0, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE OpenStack Cloud 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo-32bit", rpm:"libsnmp30-debuginfo-32bit~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~6.3.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo-32bit", rpm:"libsnmp30-debuginfo-32bit~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~6.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo-32bit", rpm:"libsnmp30-debuginfo-32bit~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~6.3.1", rls:"SLES12.0SP3"))) {
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

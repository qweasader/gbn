# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0050.1");
  script_cve_id("CVE-2018-18065", "CVE-2020-15862");
  script_tag(name:"creation_date", value:"2022-01-12 03:23:38 +0000 (Wed, 12 Jan 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 01:36:28 +0000 (Wed, 26 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0050-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0050-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220050-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SUSE-SU-2022:0050-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-snmp fixes the following issues:

CVE-2020-15862: Make extended MIB read-only (bsc#1174961)

CVE-2018-18065: Fix remote DoS in agent/helpers/table.c (bsc#1111122)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit-debuginfo", rpm:"libsnmp30-32bit-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~10.9.1", rls:"SLES15.0SP1"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0528.1");
  script_cve_id("CVE-2019-4732", "CVE-2020-2583", "CVE-2020-2593", "CVE-2020-2604", "CVE-2020-2659");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0528-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200528-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2020:0528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-ibm fixes the following issues:

Java 8.0 was updated to Service Refresh 6 Fix Pack 5 (bsc#1162972,
bsc#1160968)
CVE-2020-2583: Unlink Set of LinkedHashSets

CVE-2019-4732: Untrusted DLL search path vulnerability

CVE-2020-2593: Normalize normalization for all

CVE-2020-2604: Better serial filter handling

CVE-2020-2659: Enhance datagram socket support");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr6.5~30.63.1", rls:"SLES12.0SP5"))) {
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

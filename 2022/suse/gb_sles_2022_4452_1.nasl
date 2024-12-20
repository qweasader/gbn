# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4452.1");
  script_cve_id("CVE-2022-21619", "CVE-2022-21624", "CVE-2022-21626", "CVE-2022-21628");
  script_tag(name:"creation_date", value:"2022-12-14 04:18:35 +0000 (Wed, 14 Dec 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 21:15:13 +0000 (Tue, 18 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4452-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4452-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224452-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2022:4452-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openjdk fixes the following issues:

Update to version jdk8u352 (icedtea-3.25.0):

CVE-2022-21619,CVE-2022-21624: Fixed difficult to exploit vulnerability
 allows unauthenticated attacker with network access and can cause
 unauthorized update, insert or delete access via multiple protocols
 (bsc#1204473,bsc#1204475).

CVE-2022-21626: Fixed easily exploitable vulnerability allows
 unauthenticated attacker with network access via HTTPS to cause partial
 denial of service (bsc#1204471).

CVE-2022-21628: Fixed easily exploitable vulnerability allows
 unauthenticated attacker with network access via HTTP to cause partial
 denial of service (bsc#1204472).");

  script_tag(name:"affected", value:"'java-1_8_0-openjdk' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise Module for Legacy Software 15-SP3, SUSE Linux Enterprise Module for Legacy Software 15-SP4, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk", rpm:"java-1_8_0-openjdk~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debuginfo", rpm:"java-1_8_0-openjdk-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-debugsource", rpm:"java-1_8_0-openjdk-debugsource~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo", rpm:"java-1_8_0-openjdk-demo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-demo-debuginfo", rpm:"java-1_8_0-openjdk-demo-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel", rpm:"java-1_8_0-openjdk-devel~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-devel-debuginfo", rpm:"java-1_8_0-openjdk-devel-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless", rpm:"java-1_8_0-openjdk-headless~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openjdk-headless-debuginfo", rpm:"java-1_8_0-openjdk-headless-debuginfo~1.8.0.352~150000.3.73.1", rls:"SLES15.0SP2"))) {
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

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883040");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-2602", "CVE-2019-2684");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 17:54:00 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-04-20 02:00:25 +0000 (Sat, 20 Apr 2019)");
  script_name("CentOS Update for java-11-openjdk CESA-2019:0778 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0778");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-April/023273.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the CESA-2019:0778 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Slow conversion of BigDecimal to long (Libraries, 8211936)
(CVE-2019-2602)

  * OpenJDK: Incorrect skeleton selection in RMI registry server-side
dispatch handling (RMI, 8218453) (CVE-2019-2684)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debug", rpm:"java-11-openjdk-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo-debug", rpm:"java-11-openjdk-demo-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel-debug", rpm:"java-11-openjdk-devel-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless-debug", rpm:"java-11-openjdk-headless-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-debug", rpm:"java-11-openjdk-javadoc-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-zip", rpm:"java-11-openjdk-javadoc-zip~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-zip-debug", rpm:"java-11-openjdk-javadoc-zip-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods-debug", rpm:"java-11-openjdk-jmods-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src-debug", rpm:"java-11-openjdk-src-debug~11.0.3.7~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

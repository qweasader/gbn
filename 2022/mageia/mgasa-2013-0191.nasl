# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0191");
  script_cve_id("CVE-2013-2071");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0191");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0191.html");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105886.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.40");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10200");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2013-0191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"java/org/apache/catalina/core/AsyncContextImpl.java in Apache Tomcat 7.x
before 7.0.40 does not properly handle the throwing of a RuntimeException
in an AsyncListener in an application, which allows context-dependent
attackers to obtain sensitive request information intended for other
applications in opportunistic circumstances via an application that records
the requests that it processes (CVE-2013-2071).");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-systemv", rpm:"tomcat-systemv~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.41~3.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsvc", rpm:"tomcat-jsvc~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.41~4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.41~4.mga3", rls:"MAGEIA3"))) {
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

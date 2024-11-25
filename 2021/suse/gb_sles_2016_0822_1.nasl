# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0822.1");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-01 16:18:44 +0000 (Tue, 01 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0822-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160822-1/");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-7.0-doc/changelog.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2016:0822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following security issues.
Tomcat has been updated from 7.0.55 to 7.0.68.
* CVE-2015-5174: Directory traversal vulnerability in RequestUtil.java in
 Apache Tomcat allowed remote authenticated users to bypass intended
 SecurityManager restrictions and list a parent directory via a /..
 (slash dot dot) in a pathname used by a web application in a
 getResource, getResourceAsStream, or getResourcePaths call, as
 demonstrated by the $CATALINA_BASE/webapps directory. (bsc#967967)
* CVE-2015-5346: Session fixation vulnerability in Apache Tomcat when
 different session settings are used for deployments of multiple versions
 of the same web application, might have allowed remote attackers to
 hijack web sessions by leveraging use of a requestedSessionSSL field
 for an unintended request, related to CoyoteAdapter.java and
 Request.java. (bsc#967814)
* CVE-2015-5345: The Mapper component in Apache Tomcat processes redirects
 before considering security constraints and Filters, which allowed
 remote attackers to determine the existence of a directory via a URL
 that lacks a trailing / (slash) character. (bsc#967965)
* CVE-2015-5351: The (1) Manager and (2) Host Manager applications in
 Apache Tomcat established sessions and send CSRF tokens for arbitrary
 new requests, which allowed remote attackers to bypass a CSRF protection
 mechanism by using a token. (bsc#967812)
* CVE-2016-0706: Apache Tomcat did not place
 org.apache.catalina.manager.StatusManagerServlet on the
 org/apache/catalina/core/RestrictedServlets.properties list, which
 allowed remote authenticated users to bypass intended SecurityManager
 restrictions and read arbitrary HTTP requests, and consequently
 discover session ID values, via a crafted web application. (bsc#967815)
* CVE-2016-0714: The session-persistence implementation in Apache Tomcat
 mishandled session attributes, which allowed remote authenticated users
 to bypass intended SecurityManager restrictions and execute arbitrary
 code in a privileged context via a web application that places a crafted
 object in a session. (bsc#967964)
* CVE-2016-0763: The setGlobalContext method in
 org/apache/naming/factory/ResourceLinkFactory.java in Apache Tomcat did
 not consider whether ResourceLinkFactory.setGlobalContext callers are
 authorized, which allowed remote authenticated users to bypass intended
 SecurityManager restrictions and read or write to arbitrary application
 data, or cause a denial of service (application disruption), via a web
 application that sets a crafted global context. (bsc#967966)
See [link moved to references] for other fixes since 7.0.55");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2_2-api", rpm:"tomcat-el-2_2-api~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_2-api", rpm:"tomcat-jsp-2_2-api~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3_0-api", rpm:"tomcat-servlet-3_0-api~7.0.68~7.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.68~7.6.1", rls:"SLES12.0"))) {
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

# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:136 (tomcat5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64283");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mandrake Security Advisory MDVSA-2009:136 (tomcat5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2009\.0|2009\.1)");
  script_tag(name:"insight", value:"Multiple security vulnerabilities has been identified and fixed
in tomcat5:

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, 6.0.0 through
6.0.18, and possibly earlier versions normalizes the target pathname
before filtering the query string when using the RequestDispatcher
method, which allows remote attackers to bypass intended access
restrictions and conduct directory traversal attacks via .. (dot dot)
sequences and the WEB-INF directory in a Request (CVE-2008-5515).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18, when the Java AJP connector and mod_jk load balancing
are used, allows remote attackers to cause a denial of service
(application outage) via a crafted request with invalid headers,
related to temporary blocking of connectors that have encountered
errors, as demonstrated by an error involving a malformed HTTP Host
header (CVE-2009-0033).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and
6.0.0 through 6.0.18, when FORM authentication is used, allows
remote attackers to enumerate valid usernames via requests to
/j_security_check with malformed URL encoding of passwords, related to
improper error checking in the (1) MemoryRealm, (2) DataSourceRealm,
and (3) JDBCRealm authentication realms, as demonstrated by a %
(percent) value for the j_password parameter (CVE-2009-0580).

The calendar application in the examples web application contains an
XSS flaw due to invalid HTML which renders the XSS filtering protection
ineffective (CVE-2009-0781).

Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18 permits web applications to replace an XML parser used
for other web applications, which allows local users to read or modify
the (1) web.xml, (2) context.xml, or (3) tld files of arbitrary web
applications via a crafted application that is loaded earlier than
the target application (CVE-2009-0783).

The updated packages have been patched to prevent this. Additionally
Apache Tomcat has been upgraded to the latest 5.5.27 version for
2009.0.

Affected: 2009.0, 2009.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:136");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_tag(name:"summary", value:"The remote host is missing an update to tomcat5
announced via advisory MDVSA-2009:136.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper-eclipse", rpm:"tomcat5-jasper-eclipse~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.27~0.3.0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper-eclipse", rpm:"tomcat5-jasper-eclipse~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.27~0.3.0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}

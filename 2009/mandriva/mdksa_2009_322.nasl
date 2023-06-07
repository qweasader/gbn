# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:322 (mono)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66415");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2007-5197", "CVE-2008-3422", "CVE-2008-3906", "CVE-2009-0217");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:322 (mono)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in mono:

IOActive Inc. found a buffer overflow in Mono.Math.BigInteger class
in Mono 1.2.5.1 and previous versions, which allows arbitrary code
execution by context-dependent attackers (CVE-2007-5197).

Multiple cross-site scripting (XSS) vulnerabilities in the ASP.net
class libraries in Mono 2.0 and earlier allow remote attackers to
inject arbitrary web script or HTML via crafted attributes related to
(1) HtmlControl.cs (PreProcessRelativeReference), (2) HtmlForm.cs
(RenderAttributes), (3) HtmlInputButton (RenderAttributes),
(4) HtmlInputRadioButton (RenderAttributes), and (5) HtmlSelect
(RenderChildren) (CVE-2008-3422).

CRLF injection vulnerability in Sys.Web in Mono 2.0 and earlier allows
remote attackers to inject arbitrary HTTP headers and conduct HTTP
response splitting attacks via CRLF sequences in the query string
(CVE-2008-3906).

The XML HMAC signature system did not correctly check certain
lengths. If an attacker sent a truncated HMAC, it could bypass
authentication, leading to potential privilege escalation
(CVE-2009-0217).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

The updated packages have been patched to fix these issues.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:322");
  script_tag(name:"summary", value:"The remote host is missing an update to mono
announced via advisory MDVSA-2009:322.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"jay", rpm:"jay~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmono0", rpm:"libmono0~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmono-devel", rpm:"libmono-devel~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono", rpm:"mono~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-bytefx-data-mysql", rpm:"mono-bytefx-data-mysql~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-doc", rpm:"mono-doc~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-ibm-data-db2", rpm:"mono-ibm-data-db2~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mono0", rpm:"lib64mono0~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64mono-devel", rpm:"lib64mono-devel~1.2.5~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}

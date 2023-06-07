# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:318 (xmlsec1)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66400");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-0217", "CVE-2009-3736");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:318 (xmlsec1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple security vulnerabilities has been identified and fixed
in xmlsec1:

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1 prior to
1.2.12. An attacker could use this flaw to create a specially-crafted
XML file that forges an XML signature, allowing the attacker to
bypass authentication that is based on the XML Signature specification
(CVE-2009-0217).

All versions of libtool prior to 2.2.6b suffers from a local
privilege escalation vulnerability that could be exploited under
certain conditions to load arbitrary code (CVE-2009-3736).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update fixes this vulnerability.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:318");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/466161");
  script_tag(name:"summary", value:"The remote host is missing an update to xmlsec1
announced via advisory MDVSA-2009:318.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxmlsec1-1", rpm:"libxmlsec1-1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-devel", rpm:"libxmlsec1-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls1", rpm:"libxmlsec1-gnutls1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-gnutls-devel", rpm:"libxmlsec1-gnutls-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss1", rpm:"libxmlsec1-nss1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-nss-devel", rpm:"libxmlsec1-nss-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl1", rpm:"libxmlsec1-openssl1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxmlsec1-openssl-devel", rpm:"libxmlsec1-openssl-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-1", rpm:"lib64xmlsec1-1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-devel", rpm:"lib64xmlsec1-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls1", rpm:"lib64xmlsec1-gnutls1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-gnutls-devel", rpm:"lib64xmlsec1-gnutls-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss1", rpm:"lib64xmlsec1-nss1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-nss-devel", rpm:"lib64xmlsec1-nss-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl1", rpm:"lib64xmlsec1-openssl1~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xmlsec1-openssl-devel", rpm:"lib64xmlsec1-openssl-devel~1.2.10~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}

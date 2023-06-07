# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 288-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53361");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0131", "CVE-2003-0147");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 288-1 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20288-1");
  script_tag(name:"insight", value:"Researchers discovered two flaws in OpenSSL, a Secure Socket Layer
(SSL) library and related cryptographic tools.  Applications that are
linked against this library are generally vulnerable to attacks that
could leak the server's private key or make the encrypted session
decryptable otherwise.  The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities:

CVE-2003-0147

OpenSSL does not use RSA blinding by default, which allows local and
remote attackers to obtain the server's private key.

CVE-2003-0131

The SSL and allow remote attackers to perform an unauthorized RSA
private key operation that cause OpenSSL to leak information
regarding the relationship between ciphertext and the associated
plaintext.

For the stable distribution (woody) these problems have been fixed in
version 0.9.6c-2.woody.3.

For the old stable distribution (potato) these problems have been
fixed in version 0.9.6c-0.potato.6.

For the unstable distribution (sid) these problems have been fixed in
version 0.9.7b-1 of openssl and version 0.9.6j-1 of openssl096.");

  script_tag(name:"solution", value:"We recommend that you upgrade your openssl packages immediately and");
  script_tag(name:"summary", value:"The remote host is missing an update to openssl
announced via advisory DSA 288-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ssleay", ver:"0.9.6c-0.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.6c-0.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.6", ver:"0.9.6c-0.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.6c-0.potato.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssleay", ver:"0.9.6c-2.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.6c-2.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.6", ver:"0.9.6c-2.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.6c-2.woody.3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

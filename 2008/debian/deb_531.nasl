# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 531-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.53221");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 531-1 (php4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20531-1");
  script_tag(name:"insight", value:"Two vulnerabilities were discovered in php4:

  - CVE-2004-0594 - The memory_limit functionality in PHP 4.x up to
4.3.7, and 5.x up to 5.0.0RC3, under certain conditions such as
when register_globals is enabled, allows remote attackers to
execute arbitrary code by triggering a memory_limit abort during
execution of the zend_hash_init function and overwriting a
HashTable destructor pointer before the initialization of key data
structures is complete.

  - CVE-2004-0595 - The strip_tags function in PHP 4.x up to 4.3.7, and
5.x up to 5.0.0RC3, does not filter null (\0) characters within tag
names when restricting input to allowed tags, which allows
dangerous tags to be processed by web browsers such as Internet
Explorer and Safari, which ignore null characters and facilitate
the exploitation of cross-site scripting (XSS) vulnerabilities.

For the current stable distribution (woody), these problems have been
fixed in version 4.1.2-7.

For the unstable distribution (sid), these problems have been fixed in
version 4:4.3.8-1.

We recommend that you update your php4 package.");
  script_tag(name:"summary", value:"The remote host is missing an update to php4
announced via advisory DSA 531-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"php4-dev", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-pear", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"caudium-php4", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-curl", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-domxml", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-gd", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-imap", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-ldap", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mcal", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mhash", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-mysql", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-odbc", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-recode", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-snmp", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-sybase", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"php4-xslt", ver:"4.1.2-7", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

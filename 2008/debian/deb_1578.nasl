# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61031");
  script_cve_id("CVE-2007-3799", "CVE-2007-3806", "CVE-2007-3998", "CVE-2007-4657", "CVE-2008-2051");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1578)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1578");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1578");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1578");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php4' package(s) announced via the DSA-1578 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PHP version 4, a server-side, HTML-embedded scripting language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3799

The session_start function allows remote attackers to insert arbitrary attributes into the session cookie via special characters in a cookie that is obtained from various parameters.

CVE-2007-3806

A denial of service was possible through a malicious script abusing the glob() function.

CVE-2007-3998

Certain maliciously constructed input to the wordwrap() function could lead to a denial of service attack.

CVE-2007-4657

Large len values of the stspn() or strcspn() functions could allow an attacker to trigger integer overflows to expose memory or cause denial of service.

CVE-2008-2051

The escapeshellcmd API function could be attacked via incomplete multibyte chars.

For the stable distribution (etch), these problems have been fixed in version 6:4.4.4-8+etch6.

The php4 packages are no longer present the unstable distribution (sid).

We recommend that you upgrade your php4 package.");

  script_tag(name:"affected", value:"'php4' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-php4", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php4", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-cgi", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-cli", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-common", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-curl", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-dev", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-domxml", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-gd", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-imap", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-interbase", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-ldap", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mcal", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mcrypt", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mhash", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mysql", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-odbc", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-pear", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-pgsql", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-pspell", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-recode", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-snmp", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-sybase", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-xslt", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4", ver:"6:4.4.4-8+etch6", rls:"DEB4"))) {
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

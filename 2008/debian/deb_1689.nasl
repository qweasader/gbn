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
  script_oid("1.3.6.1.4.1.25623.1.0.63061");
  script_cve_id("CVE-2008-4242");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1689");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1689");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1689");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-1689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maksymilian Arciemowicz of securityreason.com reported that ProFTPD is vulnerable to cross-site request forgery (CSRF) attacks and executes arbitrary FTP commands via a long ftp:// URI that leverages an existing session from the FTP client implementation in a web browser.

For the stable distribution (etch) this problem has been fixed in version 1.3.0-19etch2 and in version 1.3.1-15~bpo40+1 for backports.

For the testing (lenny) and unstable (sid) distributions this problem has been fixed in version 1.3.1-15.

We recommend that you upgrade your proftpd-dfsg package.");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.0-19etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.3.0-19etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.3.0-19etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.3.0-19etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd", ver:"1.3.0-19etch2", rls:"DEB4"))) {
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

# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703356");
  script_cve_id("CVE-2015-6908");
  script_tag(name:"creation_date", value:"2015-09-11 22:00:00 +0000 (Fri, 11 Sep 2015)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3356");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3356");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3356");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openldap' package(s) announced via the DSA-3356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Denis Andzakovic discovered that OpenLDAP, a free implementation of the Lightweight Directory Access Protocol, does not properly handle BER data. An unauthenticated remote attacker can use this flaw to cause a denial of service (slapd daemon crash) via a specially crafted packet.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.4.31-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 2.4.40+dfsg-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.4.42+dfsg-2.

We recommend that you upgrade your openldap packages.");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.31-2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.40+dfsg-1+deb8u1", rls:"DEB8"))) {
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

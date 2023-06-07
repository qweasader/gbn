# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.64038");
  script_cve_id("CVE-2008-2927", "CVE-2009-1373", "CVE-2009-1375", "CVE-2009-1376");
  script_tag(name:"creation_date", value:"2009-05-25 18:59:33 +0000 (Mon, 25 May 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1805)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1805");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1805");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1805");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pidgin' package(s) announced via the DSA-1805 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Pidgin, a graphical multi-protocol instant messaging client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1373

A buffer overflow in the Jabber file transfer code may lead to denial of service or the execution of arbitrary code.

CVE-2009-1375

Memory corruption in an internal library may lead to denial of service.

CVE-2009-1376

The patch provided for the security issue tracked as CVE-2008-2927 - integer overflows in the MSN protocol handler - was found to be incomplete.

The old stable distribution (etch) is affected under the source package name gaim. However, due to build problems the updated packages couldn't be released along with the stable version. It will be released once the build problem is resolved.

For the stable distribution (lenny), these problems have been fixed in version 2.4.3-4lenny2.

For the unstable distribution (sid), these problems have been fixed in version 2.5.6-1.

We recommend that you upgrade your pidgin packages.");

  script_tag(name:"affected", value:"'pidgin' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"finch-dev", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"finch", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpurple0", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-data", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pidgin", ver:"2.4.3-4lenny2", rls:"DEB5"))) {
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

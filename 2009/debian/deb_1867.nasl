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
  script_oid("1.3.6.1.4.1.25623.1.0.64750");
  script_cve_id("CVE-2008-1671", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1867)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1867");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1867");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1867");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdelibs' package(s) announced via the DSA-1867 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in kdelibs, core libraries from the official KDE release. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1690

It was discovered that there is a use-after-free flaw in handling certain DOM event handlers. This could lead to the execution of arbitrary code, when visiting a malicious website.

CVE-2009-1698

It was discovered that there could be an uninitialised pointer when handling a Cascading Style Sheets (CSS) attr function call. This could lead to the execution of arbitrary code, when visiting a malicious website.

CVE-2009-1687

It was discovered that the JavaScript garbage collector does not handle allocation failures properly, which could lead to the execution of arbitrary code when visiting a malicious website.

For the oldstable distribution (etch), these problems have been fixed in version 4:3.5.5a.dfsg.1-8etch2.

For the stable distribution (lenny), these problems have been fixed in version 4:3.5.10.dfsg.1-0lenny2.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your kdelibs packages.");

  script_tag(name:"affected", value:"'kdelibs' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-data", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"4:3.5.5a.dfsg.1-8etch2", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-data", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"4:3.5.10.dfsg.1-0lenny2", rls:"DEB5"))) {
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

# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.71468");
  script_cve_id("CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1947");
  script_tag(name:"creation_date", value:"2012-08-10 07:02:38 +0000 (Fri, 10 Aug 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2488)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2488");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2488");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2488");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-2488 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Iceweasel, a web browser based on Firefox. The included XULRunner library provides rendering services for several other applications included in Debian.

CVE-2012-1937

Mozilla developers discovered several memory corruption bugs, which may lead to the execution of arbitrary code.

CVE-2012-1940

Abhishek Arya discovered a use-after-free problem when working with column layout with absolute positioning in a container that changes size, which may lead to the execution of arbitrary code.

CVE-2012-1947

Abhishek Arya discovered a heap buffer overflow in utf16 to latin1 character set conversion, allowing to execute arbitrary code.

Note: We'd like to advise users of Iceweasel's 3.5 branch in Debian stable to consider to upgrade to the Iceweasel 10.0 ESR (Extended Support Release) which is now available in Debian Backports. Although Debian will continue to support Iceweasel 3.5 in stable with security updates, this can only be done on a best effort base as upstream provides no such support anymore. On top of that, the 10.0 branch adds proactive security features to the browser.

For the stable distribution (squeeze), this problem has been fixed in version 3.5.16-16.

For the unstable distribution (sid), this problem has been fixed in version 10.0.5esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"3.5.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"3.5.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs2d-dbg", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs2d", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1-dbg", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.16-16", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.1.16-16", rls:"DEB6"))) {
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

# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.68088");
  script_cve_id("CVE-2010-2760", "CVE-2010-2763", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2106");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2106");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2106");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-2106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2760, CVE-2010-3167, CVE-2010-3168 Implementation errors in XUL processing allow the execution of arbitrary code.

CVE-2010-2763

An implementation error in the XPCSafeJSObjectWrapper wrapper allows the bypass of the same origin policy.

CVE-2010-2765

An integer overflow in frame handling allows the execution of arbitrary code.

CVE-2010-2766

An implementation error in DOM handling allows the execution of arbitrary code.

CVE-2010-2767

Incorrect pointer handling in the plugin code allow the execution of arbitrary code.

CVE-2010-2768

Incorrect handling of an object tag may lead to the bypass of cross site scripting filters.

CVE-2010-2769

Incorrect copy and paste handling could lead to cross site scripting.

CVE-2010-3169

Crashes in the layout engine may lead to the execution of arbitrary code.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.19-4.

For the unstable distribution (sid), these problems have been fixed in version 3.5.12-1 of the iceweasel source package (which now builds the xulrunner library binary packages).

For the experimental distribution, these problems have been fixed in version 3.6.9-1 of the iceweasel source package (which now builds the xulrunner library binary packages).

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-4", rls:"DEB5"))) {
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

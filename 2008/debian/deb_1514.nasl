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
  script_oid("1.3.6.1.4.1.25623.1.0.60500");
  script_cve_id("CVE-2007-2423", "CVE-2007-2637", "CVE-2008-0780", "CVE-2008-0781", "CVE-2008-0782", "CVE-2008-1098", "CVE-2008-1099");
  script_tag(name:"creation_date", value:"2008-03-11 20:16:32 +0000 (Tue, 11 Mar 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1514)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1514");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1514");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1514");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moin' package(s) announced via the DSA-1514 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in MoinMoin, a Python clone of WikiWiki. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2423

A cross-site-scripting vulnerability has been discovered in attachment handling.

CVE-2007-2637

Access control lists for calendars and includes were insufficiently enforced, which could lead to information disclosure.

CVE-2008-0780

A cross-site-scripting vulnerability has been discovered in the login code.

CVE-2008-0781

A cross-site-scripting vulnerability has been discovered in attachment handling.

CVE-2008-0782

A directory traversal vulnerability in cookie handling could lead to local denial of service by overwriting files.

CVE-2008-1098

Cross-site-scripting vulnerabilities have been discovered in the GUI editor formatter and the code to delete pages.

CVE-2008-1099

The macro code validates access control lists insufficiently, which could lead to information disclosure.

For the stable distribution (etch), these problems have been fixed in version 1.5.3-1.2etch1. This update also includes a bugfix with respect to the encoding of password reminder mails, which doesn't have security implications.

The old stable distribution (sarge) will not be updated due to the many changes and support for Sarge ending end of this month anyway. You're advised to upgrade to the stable distribution if you run moinmoin.

We recommend that you upgrade your moin package.");

  script_tag(name:"affected", value:"'moin' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"moinmoin-common", ver:"1.5.3-1.2etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.5.3-1.2etch1", rls:"DEB4"))) {
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
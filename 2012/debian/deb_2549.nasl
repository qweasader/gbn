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
  script_oid("1.3.6.1.4.1.25623.1.0.72207");
  script_cve_id("CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_tag(name:"creation_date", value:"2012-09-19 07:27:42 +0000 (Wed, 19 Sep 2012)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2549");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2549");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2549");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'devscripts' package(s) announced via the DSA-2549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in devscripts, a set of scripts to make the life of a Debian Package maintainer easier. The following Common Vulnerabilities and Exposures project ids have been assigned to identify them:

CVE-2012-2240: Raphael Geissert discovered that dscverify does not perform sufficient validation and does not properly escape arguments to external commands, allowing a remote attacker (as when dscverify is used by dget) to execute arbitrary code.

CVE-2012-2241: Raphael Geissert discovered that dget allows an attacker to delete arbitrary files when processing a specially-crafted .dsc or .changes file, due to insufficient input validation.

CVE-2012-2242: Raphael Geissert discovered that dget does not properly escape arguments to external commands when processing .dsc and .changes files, allowing an attacker to execute arbitrary code. This issue is limited with the fix for CVE-2012-2241, and had already been fixed in version 2.10.73 due to changes to the code, without considering its security implications.

CVE-2012-3500: Jim Meyering, Red Hat, discovered that annotate-output determines the name of temporary named pipes in a way that allows a local attacker to make it abort, leading to denial of service.

Additionally, a regression in the exit code of debdiff introduced in DSA-2409-1 has been fixed.

For the stable distribution (squeeze), these problems have been fixed in version 2.10.69+squeeze4.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed in version 2.12.3.

We recommend that you upgrade your devscripts packages.");

  script_tag(name:"affected", value:"'devscripts' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.10.69+squeeze4", rls:"DEB6"))) {
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

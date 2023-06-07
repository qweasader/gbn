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
  script_oid("1.3.6.1.4.1.25623.1.0.66773");
  script_cve_id("CVE-2009-4016", "CVE-2010-0300");
  script_tag(name:"creation_date", value:"2010-02-01 17:25:19 +0000 (Mon, 01 Feb 2010)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1980)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1980");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1980");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1980");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ircd-hybrid, ircd-ratbox' package(s) announced via the DSA-1980 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Leadbeater discovered an integer underflow that could be triggered via the LINKS command and can lead to a denial of service or the execution of arbitrary code (CVE-2009-4016). This issue affects both, ircd-hybrid and ircd-ratbox.

It was discovered that the ratbox IRC server is prone to a denial of service attack via the HELP command. The ircd-hybrid package is not vulnerable to this issue (CVE-2010-0300).

For the stable distribution (lenny), this problem has been fixed in version 1:7.2.2.dfsg.2-4+lenny1 of the ircd-hybrid package and in version 2.2.8.dfsg-2+lenny1 of ircd-ratbox.

Due to a bug in the archive software it was not possible to release the fix for the oldstable distribution (etch) simultaneously. The packages will be released as version 7.2.2.dfsg.2-3+etch1 once they become available.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your ircd-hybrid/ircd-ratbox packages.");

  script_tag(name:"affected", value:"'ircd-hybrid, ircd-ratbox' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hybrid-dev", ver:"1:7.2.2.dfsg.2-3+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ircd-hybrid", ver:"1:7.2.2.dfsg.2-3+etch1", rls:"DEB4"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"hybrid-dev", ver:"1:7.2.2.dfsg.2-4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ircd-hybrid", ver:"1:7.2.2.dfsg.2-4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ircd-ratbox-dbg", ver:"2.2.8.dfsg-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ircd-ratbox", ver:"2.2.8.dfsg-2+lenny1", rls:"DEB5"))) {
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

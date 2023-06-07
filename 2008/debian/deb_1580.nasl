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
  script_oid("1.3.6.1.4.1.25623.1.0.61033");
  script_cve_id("CVE-2008-2064");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1580)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1580");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1580");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1580");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgedview' package(s) announced via the DSA-1580 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that phpGedView, an application to provide online access to genealogical data, allowed remote attackers to gain administrator privileges due to a programming error.

Note: this problem was a fundamental design flaw in the interface (API) to connect phpGedView with external programs like content management systems. Resolving this problem was only possible by completely reworking the API, which is not considered appropriate for a security update. Since these are peripheral functions probably not used by the large majority of package users, it was decided to remove these interfaces. If you require that interface nonetheless, you are advised to use a version of phpGedView backported from Debian Lenny, which has a completely redesigned API.

For the stable distribution (etch), this problem has been fixed in version 4.0.2.dfsg-4.

For the unstable distribution (sid), this problem has been fixed in version 4.1.e+4.1.5-1.

We recommend that you upgrade your phpgedview package.");

  script_tag(name:"affected", value:"'phpgedview' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phpgedview-languages", ver:"4.0.2.dfsg-4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgedview-places", ver:"4.0.2.dfsg-4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgedview-themes", ver:"4.0.2.dfsg-4", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgedview", ver:"4.0.2.dfsg-4", rls:"DEB4"))) {
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

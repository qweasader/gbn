# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704066");
  script_cve_id("CVE-2017-16854", "CVE-2017-16921");
  script_tag(name:"creation_date", value:"2017-12-16 23:00:00 +0000 (Sat, 16 Dec 2017)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 18:15:00 +0000 (Thu, 22 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-4066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4066");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4066");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4066");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/otrs2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DSA-4066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the Open Ticket Request System which could result in information disclosure or the execution of arbitrary shell commands by logged-in agents.

For the oldstable distribution (jessie), these problems have been fixed in version 3.3.18-1+deb8u3.

For the stable distribution (stretch), these problems have been fixed in version 5.0.16-1+deb9u4.

We recommend that you upgrade your otrs2 packages.

For the detailed security status of otrs2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.3.18-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.3.18-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"5.0.16-1+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"5.0.16-1+deb9u4", rls:"DEB9"))) {
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

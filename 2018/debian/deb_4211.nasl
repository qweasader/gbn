# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704211");
  script_cve_id("CVE-2017-18266");
  script_tag(name:"creation_date", value:"2018-05-24 22:00:00 +0000 (Thu, 24 May 2018)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-14 13:33:00 +0000 (Thu, 14 Jun 2018)");

  script_name("Debian: Security Advisory (DSA-4211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4211");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4211");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4211");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xdg-utils");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xdg-utils' package(s) announced via the DSA-4211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gabriel Corona discovered that xdg-utils, a set of tools for desktop environment integration, is vulnerable to argument injection attacks. If the environment variable BROWSER in the victim host has a '%s' and the victim opens a link crafted by an attacker with xdg-open, the malicious party could manipulate the parameters used by the browser when opened. This manipulation could set, for example, a proxy to which the network traffic could be intercepted for that particular execution.

For the oldstable distribution (jessie), this problem has been fixed in version 1.1.0~rc1+git20111210-7.4+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 1.1.1-1+deb9u1.

We recommend that you upgrade your xdg-utils packages.

For the detailed security status of xdg-utils please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xdg-utils' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xdg-utils", ver:"1.1.0~rc1+git20111210-7.4+deb8u1", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xdg-utils", ver:"1.1.1-1+deb9u1", rls:"DEB9"))) {
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

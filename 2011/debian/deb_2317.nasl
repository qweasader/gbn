# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.70406");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2317");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2317");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2317");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2011-2372

Mariusz Mlynski discovered that websites could open a download dialog -- which has open as the default action --, while a user presses the ENTER key.

CVE-2011-2995

Benjamin Smedberg, Bob Clary and Jesse Ruderman discovered crashes in the rendering engine, which could lead to the execution of arbitrary code.

CVE-2011-2998

Mark Kaplan discovered an integer underflow in the JavaScript engine, which could lead to the execution of arbitrary code.

CVE-2011-2999

Boris Zbarsky discovered that incorrect handling of the window.location object could lead to bypasses of the same-origin policy.

CVE-2011-3000

Ian Graham discovered that multiple Location headers might lead to CRLF injection.

As indicated in the Lenny (oldstable) release notes, security support for the Icedove packages in the oldstable needed to be stopped before the end of the regular Lenny security maintenance life cycle. You are strongly encouraged to upgrade to stable or switch to a different mail client.

For the stable distribution (squeeze), this problem has been fixed in version 3.0.11-1+squeeze5.

For the unstable distribution (sid), this problem has been fixed in version 3.1.15-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze5", rls:"DEB6"))) {
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

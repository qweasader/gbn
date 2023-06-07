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
  script_oid("1.3.6.1.4.1.25623.1.0.840859");
  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_tag(name:"creation_date", value:"2012-01-09 08:00:14 +0000 (Mon, 09 Jan 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1306-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1306-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1306-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/906389");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozvoikko, ubufox' package(s) announced via the USN-1306-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1306-1 fixed vulnerabilities in Firefox. This update provides updated
Mozvoikko and ubufox packages for use with Firefox 9.

Original advisory details:

 Alexandre Poirot, Chris Blizzard, Kyle Huey, Scoobidiver, Christian Holler,
 David Baron, Gary Kwong, Jim Blandy, Bob Clary, Jesse Ruderman, Marcia
 Knous, and Rober Longson discovered several memory safety issues which
 could possibly be exploited to crash Firefox or execute arbitrary code as
 the user that invoked Firefox. (CVE-2011-3660)

 Aki Helin discovered a crash in the YARR regular expression library that
 could be triggered by javascript in web content. (CVE-2011-3661)

 It was discovered that a flaw in the Mozilla SVG implementation could
 result in an out-of-bounds memory access if SVG elements were removed
 during a DOMAttrModified event handler. An attacker could potentially
 exploit this vulnerability to crash Firefox. (CVE-2011-3658)

 Mario Heiderich discovered it was possible to use SVG animation accessKey
 events to detect key strokes even when JavaScript was disabled. A malicious
 web page could potentially exploit this to trick a user into interacting
 with a prompt thinking it came from the browser in a context where the user
 believed scripting was disabled. (CVE-2011-3663)

 It was discovered that it was possible to crash Firefox when scaling an OGG
 <video> element to extreme sizes. (CVE-2011-3665)");

  script_tag(name:"affected", value:"'mozvoikko, ubufox' package(s) on Ubuntu 11.04, Ubuntu 11.10.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu0.11.04.4", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.3-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu2.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"1.0.2-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

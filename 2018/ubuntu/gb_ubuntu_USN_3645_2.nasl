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
  script_oid("1.3.6.1.4.1.25623.1.0.843527");
  script_cve_id("CVE-2018-5150", "CVE-2018-5151", "CVE-2018-5152", "CVE-2018-5153", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5166", "CVE-2018-5167", "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177", "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182");
  script_tag(name:"creation_date", value:"2018-05-19 03:41:54 +0000 (Sat, 19 May 2018)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 16:06:00 +0000 (Mon, 11 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3645-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3645-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3645-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1772115");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3645-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3645-1 fixed vulnerabilities in Firefox. The update caused an issue
where users experienced long UI pauses in some circumsances. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service via application
 crash, bypass same-origin restrictions, conduct cross-site scripting (XSS)
 attacks, install lightweight themes without user interaction, spoof the
 filename in the downloads panel, or execute arbitrary code.
 (CVE-2018-5150, CVE-2018-5151, CVE-2018-5153, CVE-2018-5154,
 CVE-2018-5155, CVE-2018-5157, CVE-2018-5158, CVE-2018-5159, CVE-2018-5160,
 CVE-2018-5163, CVE-2018-5164, CVE-2018-5168, CVE-2018-5173, CVE-2018-5175,
 CVE-2018-5177, CVE-2018-5180)

 Multiple security issues were discovered with WebExtensions. If a user
 were tricked in to installing a specially crafted extension, an attacker
 could potentially exploit these to obtain sensitive information, or bypass
 security restrictions. (CVE-2018-5152, CVE-2018-5166)

 It was discovered that the web console and JavaScript debugger incorrectly
 linkified chrome: and javascript URLs. If a user were tricked in to
 clicking a specially crafted link, an attacker could potentially exploit
 this to conduct cross-site scripting (XSS) attacks. (CVE-2018-5167)

 It was discovered that dragging and dropping link text on to the home
 button could set the home page to include chrome pages. If a user were
 tricked in to dragging and dropping a specially crafted link on to the
 home button, an attacker could potentially exploit this bypass security
 restrictions. (CVE-2018-5169)

 It was discovered that the Live Bookmarks page and PDF viewer would run
 script pasted from the clipboard. If a user were tricked in to copying and
 pasting specially crafted text, an attacker could potentially exploit this
 to conduct cross-site scripting (XSS) attacks. (CVE-2018-5172)

 It was discovered that the JSON viewer incorrectly linkified javascript:
 URLs. If a user were tricked in to clicking on a specially crafted link,
 an attacker could potentially exploit this to obtain sensitive
 information. (CVE-2018-5176)

 It was discovered that dragging a file: URL on to a tab that is running in
 a different process would cause the file to open in that process. If a
 user were tricked in to dragging a file: URL, an attacker could
 potentially exploit this to bypass intended security policies.
 (CVE-2018-5181)

 It was discovered that dragging text that is a file: URL on to the
 addressbar would open the specified file. If a user were tricked in to
 dragging specially crafted text on to the addressbar, an attacker could
 potentially exploit this to bypass intended security policies.
 (CVE-2018-5182)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"60.0.1+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"60.0.1+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"60.0.1+build2-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"60.0.1+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

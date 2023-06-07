# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844018");
  script_cve_id("CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11695", "CVE-2019-11696", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-11699", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9800", "CVE-2019-9814", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821");
  script_tag(name:"creation_date", value:"2019-05-22 02:00:58 +0000 (Wed, 22 May 2019)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:15:00 +0000 (Fri, 26 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-3991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3991-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the browser
UI, trick the user in to launching local executable binaries, obtain
sensitive information, conduct cross-site scripting (XSS) attacks, or
execute arbitrary code. (CVE-2019-11691, CVE-2019-11692, CVE-2019-11693,
CVE-2019-11695, CVE-2019-11696, CVE-2019-11699, CVE-2019-11701,
CVE-2019-7317, CVE-2019-9800, CVE-2019-9814, CVE-2019-9817, CVE-2019-9819,
CVE-2019-9820, CVE-2019-9821)

It was discovered that pressing certain key combinations could bypass
addon installation prompt delays. If a user opened a specially crafted
website, an attacker could potentially exploit this to trick them in to
installing a malicious extension. (CVE-2019-11697)

It was discovered that history data could be exposed via drag and drop
of hyperlinks to and from bookmarks. If a user were tricked in to dragging
a specially crafted hyperlink to the bookmark toolbar or sidebar, and
subsequently back in to the web content area, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2019-11698)

A type confusion bug was discovered with object groups and UnboxedObjects.
If a user were tricked in to opening a specially crafted website after
enabling the UnboxedObjects feature, an attacker could potentially
exploit this to bypass security checks. (CVE-2019-9816)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0+build2-0ubuntu0.18.10.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0+build2-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
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

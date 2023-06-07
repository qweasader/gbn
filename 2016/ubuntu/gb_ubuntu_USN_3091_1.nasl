# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.842906");
  script_cve_id("CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5175", "CVE-2016-5177", "CVE-2016-5178", "CVE-2016-7549");
  script_tag(name:"creation_date", value:"2016-10-08 03:44:27 +0000 (Sat, 08 Oct 2016)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3091-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3091-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-3091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free was discovered in the V8 bindings in Blink. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5170)

A use-after-free was discovered in the V8 bindings in Blink. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5171)

An issue was discovered in V8. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
contain sensitive information from arbitrary memory locations.
(CVE-2016-5172)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5175, CVE-2016-5178)

A use-after-free was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5177)

It was discovered that Chromium does not ensure the recipient of a certain
IPC message is a valid RenderFrame or RenderWidget. An attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-7549)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.17.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.17.9-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
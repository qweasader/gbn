# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840327");
  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-2934");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-626-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-626-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-626-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.0, xulrunner-1.9' package(s) announced via the USN-626-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the browser engine. A variable could be made to
overflow causing the browser to crash. If a user were tricked into opening
a malicious web page, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2008-2785)

Billy Rios discovered that Firefox and xulrunner, as used by browsers
such as Epiphany, did not properly perform URI splitting with pipe
symbols when passed a command-line URI. If Firefox or xulrunner were
passed a malicious URL, an attacker may be able to execute local
content with chrome privileges. (CVE-2008-2933)");

  script_tag(name:"affected", value:"'firefox-3.0, xulrunner-1.9' package(s) on Ubuntu 8.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS"))) {
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

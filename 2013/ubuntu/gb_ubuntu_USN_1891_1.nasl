# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.841489");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"creation_date", value:"2013-06-27 04:31:25 +0000 (Thu, 27 Jun 2013)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1891-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1891-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1193919");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If the user
were tricked into opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1682)

Abhishek Arya discovered multiple use-after-free bugs. If the user were
tricked into opening a specially crafted message with scripting enabled,
an attacker could possibly exploit these to execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1684,
CVE-2013-1685, CVE-2013-1686)

Mariusz Mlynski discovered that user defined code within the XBL scope of
an element could be made to bypass System Only Wrappers (SOW). If a user
had scripting enabled, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-1687)

A crash was discovered when reloading a page that contained content using
the onreadystatechange event. If a user had scripting enabled, an attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2013-1690)

Johnathan Kuskos discovered that Thunderbird sent data in the body of
XMLHttpRequest HEAD requests. If a user had scripting enabled, an attacker
could exploit this to conduct Cross-Site Request Forgery (CSRF) attacks.
(CVE-2013-1692)

Paul Stone discovered a timing flaw in the processing of SVG images with
filters. If a user had scripting enabled, an attacker could exploit this
to view sensitive information. (CVE-2013-1693)

Boris Zbarsky discovered a flaw in PreserveWrapper. If a user had
scripting enabled, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute code with the
privileges of the user invoking Thunderbird. (CVE-2013-1694)

It was discovered that XrayWrappers could be bypassed to call
content-defined methods in certain circumstances. If a user had scripting
enabled, an attacker could exploit this to cause undefined behaviour.
(CVE-2013-1697)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.7+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04"))) {
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

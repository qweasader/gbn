# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840415");
  script_cve_id("CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182");
  script_tag(name:"creation_date", value:"2010-04-16 15:02:11 +0000 (Fri, 16 Apr 2010)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.10");

  script_xref(name:"Advisory-ID", value:"USN-921-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-921-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-3.5, xulrunner-1.9.1' package(s) announced via the USN-921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martijn Wargers, Josh Soref, Jesse Ruderman, and Ehsan Akhgari discovered
flaws in the browser engine of Firefox. If a user were tricked into viewing
a malicious website, a remote attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2010-0173, CVE-2010-0174)

It was discovered that Firefox could be made to access previously freed
memory. If a user were tricked into viewing a malicious website, a remote
attacker could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2010-0175,
CVE-2010-0176, CVE-2010-0177)

Paul Stone discovered that Firefox could be made to change a mouse click
into a drag and drop event. If the user could be tricked into performing
this action twice on a crafted website, an attacker could execute
arbitrary JavaScript with chrome privileges. (CVE-2010-0178)

It was discovered that the XMLHttpRequestSpy module as used by the Firebug
add-on could be used to escalate privileges within the browser. If the user
had the Firebug add-on installed and were tricked into viewing a malicious
website, an attacker could potentially run arbitrary JavaScript.
(CVE-2010-0179)

Henry Sudhof discovered that an image tag could be used as a redirect to
a mailto: URL to launch an external mail handler. (CVE-2010-0181)

Wladimir Palant discovered that Firefox did not always perform security
checks on XML content. An attacker could exploit this to bypass security
policies to load certain resources. (CVE-2010-0182)");

  script_tag(name:"affected", value:"'firefox-3.5, xulrunner-1.9.1' package(s) on Ubuntu 9.10.");

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

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.5.9+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.9+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
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

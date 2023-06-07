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
  script_oid("1.3.6.1.4.1.25623.1.0.841307");
  script_cve_id("CVE-2012-5829", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0749", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");
  script_tag(name:"creation_date", value:"2013-02-08 04:46:31 +0000 (Fri, 08 Feb 2013)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1681-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1681-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1681-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1116725");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1681-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1681-1 fixed vulnerabilities in Firefox. Due to an upstream regression,
Firefox suffered from instabilities when accessing some websites. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki Ishikawa, Bill
 Gianopoulos, Benoit Jacob, Gary Kwong, Robert O'Callahan, Jesse Ruderman,
 and Julian Seward discovered multiple memory safety issues affecting
 Firefox. If the user were tricked into opening a specially crafted page, an
 attacker could possibly exploit these to cause a denial of service via
 application crash, or potentially execute code with the privileges of the
 user invoking Firefox. (CVE-2013-0769, CVE-2013-0749, CVE-2013-0770)

 Abhishek Arya discovered several user-after-free and buffer overflows in
 Firefox. An attacker could exploit these to cause a denial of service via
 application crash, or potentially execute code with the privileges of the
 user invoking Firefox. (CVE-2013-0760, CVE-2013-0761, CVE-2013-0762,
 CVE-2013-0763, CVE-2013-0766, CVE-2013-0767, CVE-2013-0771, CVE-2012-5829)

 A stack buffer was discovered in Firefox. If the user were tricked into
 opening a specially crafted page, an attacker could possibly exploit this
 to cause a denial of service via application crash, or potentially execute
 code with the privileges of the user invoking Firefox. (CVE-2013-0768)

 Masato Kinugawa discovered that Firefox did not always properly display URL
 values in the address bar. A remote attacker could exploit this to conduct
 URL spoofing and phishing attacks. (CVE-2013-0759)

 Atte Kettunen discovered that Firefox did not properly handle HTML tables
 with a large number of columns and column groups. If the user were tricked
 into opening a specially crafted page, an attacker could exploit this to
 cause a denial of service via application crash, or potentially execute
 code with the privileges of the user invoking Firefox. (CVE-2013-0744)

 Jerry Baker discovered that Firefox did not always properly handle
 threading when performing downloads over SSL connections. An attacker could
 exploit this to cause a denial of service via application crash.
 (CVE-2013-0764)

 Olli Pettay and Boris Zbarsky discovered flaws in the Javascript engine of
 Firefox. An attacker could cause a denial of service via application crash,
 or potentially execute code with the privileges of the user invoking
 Firefox. (CVE-2013-0745, CVE-2013-0746)

 Jesse Ruderman discovered a flaw in the way Firefox handled plugins. If a
 user were tricked into opening a specially crafted page, a remote attacker
 could exploit this to bypass security protections to conduct clickjacking
 attacks. (CVE-2013-0747)

 Jesse Ruderman discovered an information leak in Firefox. An attacker could
 exploit this to reveal memory address layout which could help in bypassing
 ASLR protections. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"18.0.2+build1-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"18.0.2+build1-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"18.0.2+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"18.0.2+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
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
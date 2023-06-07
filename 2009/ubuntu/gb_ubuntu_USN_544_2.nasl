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
  script_oid("1.3.6.1.4.1.25623.1.0.840097");
  script_cve_id("CVE-2007-4572", "CVE-2007-5398");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-544-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-544-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-544-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/163042");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-544-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-544-1 fixed two vulnerabilities in Samba. Fixes for CVE-2007-5398
are unchanged, but the upstream changes for CVE-2007-4572 introduced a
regression in all releases which caused Linux smbfs mounts to fail.
Additionally, Dapper and Edgy included an incomplete patch which caused
configurations using NetBIOS to fail. A proper fix for these regressions
does not exist at this time, and so the patch addressing CVE-2007-4572
has been removed. This vulnerability is believed to be an unexploitable
denial of service, but a future update will address this issue. We
apologize for the inconvenience.

Original advisory details:

 Samba developers discovered that nmbd could be made to overrun
 a buffer during the processing of GETDC logon server requests.
 When samba is configured as a Primary or Backup Domain Controller,
 a remote attacker could send malicious logon requests and possibly
 cause a denial of service. (CVE-2007-4572)

 Alin Rad Pop of Secunia Research discovered that nmbd did not properly
 check the length of netbios packets. When samba is configured as a WINS
 server, a remote attacker could send multiple crafted requests resulting
 in the execution of arbitrary code with root privileges. (CVE-2007-5398)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.22-1ubuntu3.5", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.22-1ubuntu4.4", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.24-2ubuntu1.4", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"3.0.26a-1ubuntu2.2", rls:"UBUNTU7.10"))) {
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

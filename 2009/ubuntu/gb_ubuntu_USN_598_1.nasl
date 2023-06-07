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
  script_oid("1.3.6.1.4.1.25623.1.0.840310");
  script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-0882", "CVE-2008-1373");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-598-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-598-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-598-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cupsys' package(s) announced via the USN-598-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CUPS administration interface contained a heap-
based overflow flaw. A local attacker, and a remote attacker if printer
sharing is enabled, could send a malicious request and possibly execute
arbitrary code as the non-root user in Ubuntu 6.06 LTS, 6.10, and 7.04.
In Ubuntu 7.10, attackers would be isolated by the AppArmor CUPS profile.
(CVE-2008-0047)

It was discovered that the hpgl filter in CUPS did not properly validate
its input when parsing parameters. If a crafted HP-GL/2 file were printed,
an attacker could possibly execute arbitrary code as the non-root user
in Ubuntu 6.06 LTS, 6.10, and 7.04. In Ubuntu 7.10, attackers would be
isolated by the AppArmor CUPS profile. (CVE-2008-0053)

It was discovered that CUPS had a flaw in its managing of remote shared
printers via IPP. A remote attacker could send a crafted UDP packet and
cause a denial of service or possibly execute arbitrary code as the
non-root user in Ubuntu 6.06 LTS, 6.10, and 7.04. In Ubuntu 7.10,
attackers would be isolated by the AppArmor CUPS profile. (CVE-2008-0882)

It was discovered that CUPS did not properly perform bounds checking in
its GIF decoding routines. If a crafted GIF file were printed, an attacker
could possibly execute arbitrary code as the non-root user in Ubuntu 6.06
LTS, 6.10, and 7.04. In Ubuntu 7.10, attackers would be isolated by the
AppArmor CUPS profile. (CVE-2008-1373)");

  script_tag(name:"affected", value:"'cupsys' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.2-0ubuntu0.6.06.8", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.4-2ubuntu3.3", rls:"UBUNTU6.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.8-0ubuntu8.3", rls:"UBUNTU7.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.2-1ubuntu7.6", rls:"UBUNTU7.10"))) {
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

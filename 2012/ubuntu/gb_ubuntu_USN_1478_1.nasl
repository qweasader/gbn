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
  script_oid("1.3.6.1.4.1.25623.1.0.841046");
  script_cve_id("CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3940", "CVE-2011-3945", "CVE-2011-3947", "CVE-2011-3951", "CVE-2011-3952", "CVE-2011-4031", "CVE-2012-0848", "CVE-2012-0850", "CVE-2012-0851", "CVE-2012-0852", "CVE-2012-0853", "CVE-2012-0858", "CVE-2012-0859", "CVE-2012-0947");
  script_tag(name:"creation_date", value:"2012-06-19 04:11:48 +0000 (Tue, 19 Jun 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1478-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1478-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libav' package(s) announced via the USN-1478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed DV files. If a user were tricked into opening a
crafted DV file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. This issue only affected Ubuntu 11.10.
(CVE-2011-3929, CVE-2011-3936)

Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed NSV files. If a user were tricked into opening a
crafted NSV file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. This issue only affected Ubuntu 11.04 and
Ubuntu 11.10. (CVE-2011-3940)

Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed Kega Game Video (KGV1) files. If a user were
tricked into opening a crafted Kega Game Video (KGV1) file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program. This
issue only affected Ubuntu 11.04 and Ubuntu 11.10. (CVE-2011-3945)

Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed MJPEG-B files. If a user were tricked into
opening a crafted MJPEG-B file, an attacker could cause a denial of service
via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. This issue only affected
Ubuntu 11.04 and Ubuntu 11.10. (CVE-2011-3947)

Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed DPCM files. If a user were tricked into opening a
crafted DPCM file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. This issue only affected Ubuntu 11.04 and
Ubuntu 11.10. (CVE-2011-3951)

Mateusz Jurczyk and Gynvael Coldwind discovered that Libav incorrectly
handled certain malformed KMVC files. If a user were tricked into opening a
crafted KMVC file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. This issue only affected Ubuntu 11.04 and
Ubuntu 11.10. (CVE-2011-3952)

Jeong Wook Oh discovered that Libav incorrectly handled certain malformed
ASF files. If a user were tricked into opening a crafted ASF file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. This issue only affected Ubuntu 11.10. (CVE-2011-4031)

It was discovered that Libav incorrectly handled certain malformed
Westwood SNDx files. If a user were tricked into opening a crafted Westwood
SNDx file, an attacker ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libav' package(s) on Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.6.6-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.6.6-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec53", ver:"4:0.7.6-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat53", ver:"4:0.7.6-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec53", ver:"4:0.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat53", ver:"4:0.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

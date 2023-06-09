# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0001");
  script_cve_id("CVE-2019-12402");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-16T04:59:58+0000");
  script_tag(name:"last_modification", value:"2022-05-16 04:59:58 +0000 (Mon, 16 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-14 03:15:00 +0000 (Sat, 14 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2020-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0001.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25365");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QLJIK2AUOZOWXR3S5XXBUNMOF3RTHTI7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-compress' package(s) announced via the MGASA-2020-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pdated apache-commons-compress packages fix security vulnerability:

A resource consumption vulnerability was discovered in apache-commons-
compress in the way NioZipEncoding encodes filenames. Applications that
use Compress to create archives, with one of the filenames within the
archive being controlled by the user, may be vulnerable to this flaw.
A remote attacker could exploit this flaw to cause an infinite loop during
the archive creation, thus leading to a denial of service (CVE-2019-12402).");

  script_tag(name:"affected", value:"'apache-commons-compress' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress", rpm:"apache-commons-compress~1.19~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress-javadoc", rpm:"apache-commons-compress-javadoc~1.19~1.mga7", rls:"MAGEIA7"))) {
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

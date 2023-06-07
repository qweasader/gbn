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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0420");
  script_cve_id("CVE-2022-3756");
  script_tag(name:"creation_date", value:"2022-11-14 04:25:42 +0000 (Mon, 14 Nov 2022)");
  script_version("2022-11-23T10:13:09+0000");
  script_tag(name:"last_modification", value:"2022-11-23 10:13:09 +0000 (Wed, 23 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0420");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0420.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31074");
  script_xref(name:"URL", value:"https://github.com/Exiv2/exiv2/issues/2406#issuecomment-1302816492");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the MGASA-2022-0420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Affected is the function QuickTimeVideo::userDataDecoder of the file
quicktimevideo.cpp of the component QuickTime Video Handler. The
manipulation leads to integer overflow. It is possible to launch the
attack remotely. (CVE-2022-3756)");

  script_tag(name:"affected", value:"'exiv2' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2-devel", rpm:"lib64exiv2-devel~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2_27", rpm:"lib64exiv2_27~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2_27", rpm:"libexiv2_27~0.27.3~1.5.mga8", rls:"MAGEIA8"))) {
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

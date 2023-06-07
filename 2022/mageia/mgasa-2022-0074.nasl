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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0074");
  script_cve_id("CVE-2021-28021", "CVE-2021-42715", "CVE-2021-42716");
  script_tag(name:"creation_date", value:"2022-02-18 03:17:16 +0000 (Fri, 18 Feb 2022)");
  script_version("2022-05-16T04:59:58+0000");
  script_tag(name:"last_modification", value:"2022-05-16 04:59:58 +0000 (Mon, 16 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-20 20:31:00 +0000 (Wed, 20 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0074");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0074.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29937");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TPIWID3WJ3SMCA23W52QU3RW6AU7JCA7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zxing-cpp' package(s) announced via the MGASA-2022-0074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow vulnerability in function stbi__extend_receive in stb_image.h
in stb 2.26 via a crafted JPEG file. (CVE-2021-28021)

An issue was discovered in stb stb_image.h 1.33 through 2.27. The HDR loader
parsed truncated end-of-file RLE scanlines as an infinite sequence of
zero-length runs. An attacker could potentially have caused denial of service
in applications using stb_image by submitting crafted HDR files.
(CVE-2021-42715)

An issue was discovered in stb stb_image.h 2.27. The PNM loader incorrectly
interpreted 16-bit PGM files as 8-bit when converting to RGBA, leading to a
buffer overflow when later reinterpreting the result as a 16-bit buffer. An
attacker could potentially have crashed a service using stb_image, or read up
to 1024 bytes of non-consecutive heap data without control over the read
location. (CVE-2021-42716)");

  script_tag(name:"affected", value:"'zxing-cpp' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64zxing-devel", rpm:"lib64zxing-devel~1.1.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zxing1", rpm:"lib64zxing1~1.1.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzxing-devel", rpm:"libzxing-devel~1.1.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzxing1", rpm:"libzxing1~1.1.1~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zxing-cpp", rpm:"zxing-cpp~1.1.1~2.1.mga8", rls:"MAGEIA8"))) {
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

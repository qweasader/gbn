# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131184");
  script_cve_id("CVE-2015-7555");
  script_tag(name:"creation_date", value:"2016-01-15 06:28:59 +0000 (Fri, 15 Jan 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0020");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0020.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17376");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-January/174870.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib' package(s) announced via the MGASA-2016-0020 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow vulnerability was found in giffix utility of
giflib when processing records of the type 'IMAGE_DESC_RECORD_TYPE' due to
the allocated size of 'LineBuffer' equaling the value of the logical
screen width, 'GifFileIn->SWidth', while subsequently having
'GifFileIn->Image.Width' bytes of data written to it (CVE-2015-7555).");

  script_tag(name:"affected", value:"'giflib' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"giflib", rpm:"giflib~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs", rpm:"giflib-progs~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gif-devel", rpm:"lib64gif-devel~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gif4", rpm:"lib64gif4~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif-devel", rpm:"libgif-devel~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif4", rpm:"libgif4~4.2.3~4.2.mga5", rls:"MAGEIA5"))) {
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

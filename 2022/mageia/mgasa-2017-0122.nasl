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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0122");
  script_cve_id("CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9573");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-11T04:17:29+0000");
  script_tag(name:"last_modification", value:"2022-04-11 04:17:29 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 15:39:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2017-0122)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0122");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0122.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20559");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2017-0838.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg' package(s) announced via the MGASA-2017-0122 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer overflows in the opj_tcd_init_tile function in tcd.c in
OpenJPEG, as used in PDFium in Google Chrome before 52.0.2743.116, allow
remote attackers to cause a denial of service (heap-based buffer overflow)
or possibly have unspecified other impact via crafted JPEG 2000 data.
(CVE-2016-5139)

Multiple integer overflows in the opj_tcd_init_tile function in tcd.c in
OpenJPEG, as used in PDFium in Google Chrome before 53.0.2785.89 on
Windows and OS X and before 53.0.2785.92 on Linux, allow remote attackers
to cause a denial of service (heap-based buffer overflow) or possibly have
unspecified other impact via crafted JPEG 2000 data. (CVE-2016-5158)

Multiple integer overflows in OpenJPEG, as used in PDFium in Google Chrome
before 53.0.2785.89 on Windows and OS X and before 53.0.2785.92 on Linux,
allow remote attackers to cause a denial of service (heap-based buffer
overflow) or possibly have unspecified other impact via crafted JPEG 2000
data that is mishandled during opj_aligned_malloc calls in dwt.c and t1.c.
(CVE-2016-5159)

Integer overflow in the opj_pi_create_decode function in pi.c in OpenJPEG
allows remote attackers to execute arbitrary code via a crafted JP2 file,
which triggers an out-of-bounds read or write. (CVE-2016-7163)

An out-of-bounds read vulnerability was found in OpenJPEG, in the
j2k_to_image tool. Converting a specially crafted JPEG2000 file to another
format could cause the application to crash or, potentially, disclose some
data from the heap. (CVE-2016-9573");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg-devel", rpm:"lib64openjpeg-devel~1.5.2~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg5", rpm:"lib64openjpeg5~1.5.2~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg-devel", rpm:"libopenjpeg-devel~1.5.2~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg5", rpm:"libopenjpeg5~1.5.2~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.5.2~5.2.mga5", rls:"MAGEIA5"))) {
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

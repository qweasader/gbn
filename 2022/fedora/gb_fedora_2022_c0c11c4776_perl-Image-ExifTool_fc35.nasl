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
  script_oid("1.3.6.1.4.1.25623.1.0.819644");
  script_version("2022-05-23T03:07:35+0000");
  script_cve_id("CVE-2022-23935");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-23 03:07:35 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-19 21:20:00 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2022-02-04 02:05:23 +0000 (Fri, 04 Feb 2022)");
  script_name("Fedora: Security Advisory for perl-Image-ExifTool (FEDORA-2022-c0c11c4776)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-c0c11c4776");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BKMOJHTMTSAYV7B2A27CBMM7IBAZIRWE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Image-ExifTool'
  package(s) announced via the FEDORA-2022-c0c11c4776 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ExifTool is a Perl module with an included command-line application for
reading and writing meta information in image, audio, and video files.
It reads EXIF, GPS, IPTC, XMP, JFIF, MakerNotes, GeoTIFF, ICC Profile,
Photoshop IRB, FlashPix, AFCP, and ID3 meta information from JPG, JP2,
TIFF, GIF, PNG, MNG, JNG, MIFF, EPS, PS, AI, PDF, PSD, BMP, THM, CRW,
CR2, MRW, NEF, PEF, ORF, DNG, and many other types of images. ExifTool
also extracts information from the maker notes of many digital cameras
by various manufacturers including Canon, Casio, FujiFilm, GE, HP,
JVC/Victor, Kodak, Leaf, Minolta/Konica-Minolta, Nikon, Olympus/Epson,
Panasonic/Leica, Pentax/Asahi, Reconyx, Ricoh, Samsung, Sanyo,
Sigma/Foveon, and Sony.");

  script_tag(name:"affected", value:"'perl-Image-ExifTool' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-ExifTool", rpm:"perl-Image-ExifTool~12.38~1.fc35", rls:"FC35"))) {
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
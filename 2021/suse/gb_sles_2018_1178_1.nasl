# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1178.1");
  script_cve_id("CVE-2017-1000476", "CVE-2017-10928", "CVE-2017-11450", "CVE-2017-14325", "CVE-2017-17887", "CVE-2017-18250", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2018-10177", "CVE-2018-8960", "CVE-2018-9018", "CVE-2018-9135");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1178-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181178-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:1178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:
- CVE-2017-14325: In ImageMagick, a memory leak vulnerability was found in
 the function PersistPixelCache in magick/cache.c, which allowed
 attackers to cause a denial of service (memory consumption in
 ReadMPCImage in coders/mpc.c) via a crafted file. [bsc#1058635]
- CVE-2017-17887: In ImageMagick, a memory leak vulnerability was found in
 the function GetImagePixelCache in magick/cache.c, which allowed
 attackers to cause a denial of service via a crafted MNG image file that
 is processed by ReadOneMNGImage. [bsc#1074117]
- CVE-2017-18250: A NULL pointer dereference vulnerability was found in
 the function LogOpenCLBuildFailure in MagickCore/opencl.c, which could
 lead to a denial of service via a crafted file. [bsc#1087039]
- CVE-2017-18251: A memory leak vulnerability was found in the function
 ReadPCDImage in coders/pcd.c, which could lead to a denial of service
 via a crafted file. [bsc#1087037]
- CVE-2017-18252: The MogrifyImageList function in MagickWand/mogrify.c
 could allow attackers to cause a denial of service via a crafted file.
 [bsc#1087033]
- CVE-2017-18254: A memory leak vulnerability was found in the function
 WriteGIFImage in coders/gif.c, which could lead to denial of service
 via a crafted file. [bsc#1087027]
- CVE-2018-8960: The ReadTIFFImage function in coders/tiff.c in
 ImageMagick did not properly restrict memory allocation, leading to a
 heap-based buffer over-read. [bsc#1086782]
- CVE-2018-9018: divide-by-zero in the ReadMNGImage function of
 coders/png.c. Attackers could leverage this vulnerability to cause a
 crash and denial of service via a crafted mng file. [bsc#1086773]
- CVE-2018-9135: heap-based buffer over-read in IsWEBPImageLossless in
 coders/webp.c could lead to denial of service. [bsc#1087825]
- CVE-2018-10177: In ImageMagick, there was an infinite loop in the
 ReadOneMNGImage function of the coders/png.c file. Remote attackers
 could leverage this vulnerability to cause a denial of service via a
 crafted mng file. [bsc#1089781]
- CVE-2017-10928: a heap-based buffer over-read in the GetNextToken
 function in token.c could allow attackers to obtain sensitive
 information from process memory or possibly have unspecified other
 impact via a crafted SVG document that is mishandled in the
 GetUserSpaceCoordinateValue function in coders/svg.c. [bsc#1047356]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~71.54.5", rls:"SLES12.0SP3"))) {
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

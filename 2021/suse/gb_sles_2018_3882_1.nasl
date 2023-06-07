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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3882.1");
  script_cve_id("CVE-2017-11591", "CVE-2017-11683", "CVE-2017-14859", "CVE-2017-14862", "CVE-2017-14864", "CVE-2017-17669", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-11531");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3882-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183882-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2018:3882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:
CVE-2017-11591: A floating point exception in the Exiv2::ValueType
 function could lead to a remote denial of service attack via crafted
 input. (bsc#1050257)

CVE-2017-14864: An invalid memory address dereference was discovered in
 Exiv2::getULong in types.cpp. The vulnerability caused a segmentation
 fault and application crash, which lead to denial of service.
 (bsc#1060995)

CVE-2017-14862: An invalid memory address dereference was discovered in
 Exiv2::DataValue::read in value.cpp. The vulnerability caused a
 segmentation fault and application crash, which lead to denial of
 service. (bsc#1060996)

CVE-2017-14859: An invalid memory address dereference was discovered in
 Exiv2::StringValueBase::read in value.cpp. The vulnerability caused a
 segmentation fault and application crash, which lead to denial of
 service. (bsc#1061000)

CVE-2017-11683: There is a reachable assertion in the
 Internal::TiffReader::visitDirectory function in tiffvisitor.cpp that
 could lead to a remote denial of service attack via crafted input.
 (bsc#1051188)

CVE-2017-17669: There is a heap-based buffer over-read in the
 Exiv2::Internal::PngChunk::keyTXTChunk function of pngchunk_int.cpp. A
 crafted PNG file would lead to a remote denial of service attack.
 (bsc#1072928)

CVE-2018-10958: In types.cpp a large size value might have lead to a
 SIGABRT during an attempt at memory allocation for an
 Exiv2::Internal::PngChunk::zlibUncompress call. (bsc#1092952)

CVE-2018-10998: readMetadata in jp2image.cpp allowed remote attackers to
 cause a denial of service (SIGABRT) by triggering an incorrect Safe::add
 call. (bsc#1093095)

CVE-2018-11531: Exiv2 had a heap-based buffer overflow in getData in
 preview.cpp. (bsc#1095070)");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.23~12.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.23~12.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12", rpm:"libexiv2-12~0.23~12.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-12-debuginfo", rpm:"libexiv2-12-debuginfo~0.23~12.5.1", rls:"SLES12.0SP3"))) {
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

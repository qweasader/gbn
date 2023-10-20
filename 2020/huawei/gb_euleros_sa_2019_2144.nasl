# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2144");
  script_cve_id("CVE-2017-1000126", "CVE-2017-17723", "CVE-2018-10958", "CVE-2018-10998", "CVE-2018-10999", "CVE-2018-11531", "CVE-2018-14046", "CVE-2018-17282", "CVE-2018-17581", "CVE-2018-19107", "CVE-2018-19108", "CVE-2018-19535", "CVE-2018-20096", "CVE-2018-20098", "CVE-2018-20099", "CVE-2019-13112");
  script_tag(name:"creation_date", value:"2020-01-23 12:36:15 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for exiv2 (EulerOS-SA-2019-2144)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2144");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2144");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'exiv2' package(s) announced via the EulerOS-SA-2019-2144 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Exiv2 0.26 has a heap-based buffer over-read in WebPImage::decodeChunks in webpimage.cpp.(CVE-2018-14046)

There is a heap-based buffer over-read in the Exiv2::tEXtToDataBuf function of pngimage.cpp in Exiv2 0.27-RC3. A crafted input will lead to a remote denial of service attack.(CVE-2018-20096)

There is a heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2 0.27-RC3. A crafted input will lead to a remote denial of service attack.(CVE-2018-20098)

There is an infinite loop in Exiv2::Jp2Image::encodeJp2Header of jp2image.cpp in Exiv2 0.27-RC3. A crafted input will lead to a remote denial of service attack.(CVE-2018-20099)

A PngChunk::parseChunkContent uncontrolled memory allocation in Exiv2 through 0.27.1 allows an attacker to cause a denial of service (crash due to an std::bad_alloc exception) via a crafted PNG image file.(CVE-2019-13112)

CiffDirectory::readDirectory() at crwimage_int.cpp in Exiv2 0.26 has excessive stack consumption due to a recursive function, leading to Denial of service.(CVE-2018-17581)

In Exiv2 0.26 and previous versions, PngChunk::readRawProfile in pngchunk_int.cpp may cause a denial of service (application crash due to a heap-based buffer over-read) via a crafted PNG file.(CVE-2018-19535)

In types.cpp in Exiv2 0.26, a large size value may lead to a SIGABRT during an attempt at memory allocation for an Exiv2::Internal::PngChunk::zlibUncompress call.(CVE-2018-10958)

An issue was discovered in Exiv2 0.26. readMetadata in jp2image.cpp allows remote attackers to cause a denial of service (SIGABRT) by triggering an incorrect Safe::add call.(CVE-2018-10998)

An issue was discovered in Exiv2 0.26. The Exiv2::Internal::PngChunk::parseTXTChunk function has a heap-based buffer over-read.(CVE-2018-10999)

In Exiv2 0.26, Exiv2::PsdImage::readMetadata in psdimage.cpp in the PSD image reader may suffer from a denial of service (infinite loop) caused by an integer overflow via a crafted PSD image file.(CVE-2018-19108)

In Exiv2 0.26, Exiv2::IptcParser::decode in iptc.cpp (called from psdimage.cpp in the PSD image reader) may suffer from a denial of service (heap-based buffer over-read) caused by an integer overflow via a crafted PSD image file.(CVE-2018-19107)

An issue was discovered in Exiv2 v0.26. The function Exiv2::DataValue::copy in value.cpp has a NULL pointer dereference.(CVE-2018-17282)

exiv2 0.26 contains a Stack out of bounds read in webp parser(CVE-2017-1000126)

In Exiv2 0.26, there is a heap-based buffer over-read in the Exiv2::Image::byteSwap4 function in image.cpp. Remote attackers can exploit this vulnerability to disclose memory data or cause a denial of service via a crafted TIFF file.(CVE-2017-17723)

Exiv2 0.26 has a heap-based buffer overflow in getData in preview.cpp.(CVE-2018-11531)");

  script_tag(name:"affected", value:"'exiv2' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-libs", rpm:"exiv2-libs~0.26~3.h9.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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

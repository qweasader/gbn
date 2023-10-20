# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1257");
  script_cve_id("CVE-2017-14139", "CVE-2017-14224", "CVE-2017-14682", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-15033", "CVE-2017-15281");
  script_tag(name:"creation_date", value:"2020-01-23 11:01:56 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 00:15:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for ImageMagick (EulerOS-SA-2017-1257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1257");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1257");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ImageMagick' package(s) announced via the EulerOS-SA-2017-1257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow in WritePCXImage in coders/pcx.c in ImageMagick 7.0.6-8 Q16 allows remote attackers to cause a denial of service or code execution via a crafted file.(CVE-2017-14224)

GetNextToken in MagickCore/token.c in ImageMagick 7.0.6 allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted SVG document, a different vulnerability than CVE-2017-10928.(CVE-2017-14682)

ImageMagick version 7.0.7-2 contains a memory leak in ReadYUVImage in coders/yuv.c.(CVE-2017-15033)

ImageMagick 7.0.7-0 Q16 has a NULL pointer dereference vulnerability in ReadEnhMetaFile in coders/emf.c.(CVE-2017-15016)

ImageMagick 7.0.7-0 Q16 has a NULL pointer dereference vulnerability in ReadOneMNGImage in coders/png.c.(CVE-2017-15017)

ImageMagick 7.0.6-2 has a memory leak vulnerability in WriteMSLImage in coders/msl.c.(CVE-2017-14139)

ReadPSDImage in coders/psd.c in ImageMagick 7.0.7-6 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted file, related to 'Conditional jump or move depends on uninitialised value(s).'(CVE-2017-15281)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.8.9~15.h14", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.8.9~15.h14", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.7.8.9~15.h14", rls:"EULEROS-2.0SP1"))) {
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

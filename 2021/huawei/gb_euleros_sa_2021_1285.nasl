# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1285");
  script_cve_id("CVE-2016-10271", "CVE-2017-11335", "CVE-2017-16232", "CVE-2017-9404");
  script_tag(name:"creation_date", value:"2021-02-22 08:14:33 +0000 (Mon, 22 Feb 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 12:00:07 +0000 (Thu, 20 Jul 2017)");

  script_name("Huawei EulerOS: Security Advisory for compat-libtiff3 (EulerOS-SA-2021-1285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1285");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1285");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'compat-libtiff3' package(s) announced via the EulerOS-SA-2021-1285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tools/tiffcrop.c in LibTIFF 4.0.7 allows remote attackers to cause a denial of service (heap-based buffer over-read and buffer overflow) or possibly have unspecified other impact via a crafted TIFF image, related to 'READ of size 1' and libtiff/tif_fax3.c:413:13.(CVE-2016-10271)

In LibTIFF 4.0.7, a memory leak vulnerability was found in the function OJPEGReadHeaderInfoSecTablesQTable in tif_ojpeg.c, which allows attackers to cause a denial of service via a crafted file.(CVE-2017-9404)

LibTIFF 4.0.8 has multiple memory leak vulnerabilities, which allow attackers to cause a denial of service (memory consumption), as demonstrated by tif_open.c, tif_lzw.c, and tif_aux.c. NOTE: Third parties were unable to reproduce the issue.(CVE-2017-16232)

There is a heap based buffer overflow in tools/tiff2pdf.c of LibTIFF 4.0.8 via a PlanarConfig=Contig image, which causes a more than one hundred bytes out-of-bounds write (related to the ZIPDecode function in tif_zip.c). A crafted input may lead to a remote denial of service attack or an arbitrary code execution attack.(CVE-2017-11335)");

  script_tag(name:"affected", value:"'compat-libtiff3' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"compat-libtiff3", rpm:"compat-libtiff3~3.9.4~11.h20", rls:"EULEROS-2.0SP2"))) {
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

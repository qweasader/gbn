# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2253");
  script_cve_id("CVE-2020-35655", "CVE-2021-25287", "CVE-2021-25288", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923", "CVE-2021-28675", "CVE-2021-28676", "CVE-2021-28677", "CVE-2021-28678");
  script_tag(name:"creation_date", value:"2021-08-09 10:10:36 +0000 (Mon, 09 Aug 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-08 16:33:17 +0000 (Tue, 08 Jun 2021)");

  script_name("Huawei EulerOS: Security Advisory for python-pillow (EulerOS-SA-2021-2253)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2253");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-2253");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-pillow' package(s) announced via the EulerOS-SA-2021-2253 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for a BLP container, and thus an attempted memory allocation can be very large.(CVE-2021-27921)

Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICNS container, and thus an attempted memory allocation can be very large.(CVE-2021-27922)

Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the reported size of a contained image is not properly checked for an ICO container, and thus an attempted memory allocation can be very large.(CVE-2021-27923)

In Pillow before 8.1.0, SGIRleDecode has a 4-byte buffer over-read when decoding crafted SGI RLE image files because offsets and length tables are mishandled.(CVE-2020-35655)

An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile lacked a sanity check on the number of input layers relative to the size of the data block. This could lead to a DoS on Image.open prior to Image.load.(CVE-2021-28675)

An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the block advance was non-zero, potentially leading to an infinite loop on load.(CVE-2021-28676)

An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.(CVE-2021-28677)

An issue was discovered in Pillow before 8.2.0. For BLP data, BlpImagePlugin did not properly check that reads (after jumping to file offsets) returned data. This could lead to a DoS where the decoder could be run a large number of times on empty data.(CVE-2021-28678)

An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in j2ku_graya_la.(CVE-2021-25287)

An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in j2ku_gray_i.(CVE-2021-25288)");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~5.3.0~4.h11.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1940");
  script_cve_id("CVE-2018-21247", "CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");
  script_tag(name:"creation_date", value:"2020-09-04 16:35:25 +0000 (Fri, 04 Sep 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 14:07:53 +0000 (Tue, 28 Jul 2020)");

  script_name("Huawei EulerOS: Security Advisory for libvncserve (EulerOS-SA-2020-1940)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1940");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1940");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libvncserve' package(s) announced via the EulerOS-SA-2020-1940 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in LibVNCServer before 0.9.13. There is an information leak (of uninitialized memory contents) in the libvncclient/rfbproto.c ConnectToRFBRepeater function.(CVE-2018-21247)

libvncclient/sockets.c in LibVNCServer before 0.9.13 has a buffer overflow via a long socket filename.(CVE-2019-20839)

An issue was discovered in LibVNCServer before 0.9.13. libvncserver/rfbregion.c has a NULL pointer dereference.(CVE-2020-14397)

An issue was discovered in LibVNCServer before 0.9.13. An improperly closed TCP connection causes an infinite loop in libvncclient/sockets.c.(CVE-2020-14398)

An issue was discovered in LibVNCServer before 0.9.13. Byte-aligned data is accessed through uint32_t pointers in libvncclient/rfbproto.c.(CVE-2020-14399)

An issue was discovered in LibVNCServer before 0.9.13. Byte-aligned data is accessed through uint16_t pointers in libvncserver/translate.c.(CVE-2020-14400)

An issue was discovered in LibVNCServer before 0.9.13. libvncserver/scale.c has a pixel_value integer overflow.(CVE-2020-14401)

An issue was discovered in LibVNCServer before 0.9.13. libvncserver/corre.c allows out-of-bounds access via encodings.(CVE-2020-14402)

An issue was discovered in LibVNCServer before 0.9.13. libvncserver/hextile.c allows out-of-bounds access via encodings.(CVE-2020-14403)

An issue was discovered in LibVNCServer before 0.9.13. libvncserver/rre.c allows out-of-bounds access via encodings.(CVE-2020-14404)

An issue was discovered in LibVNCServer before 0.9.13. libvncclient/rfbproto.c does not limit TextChat size.(CVE-2020-14405)");

  script_tag(name:"affected", value:"'libvncserve' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.9~12.h12.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver-devel", rpm:"libvncserver-devel~0.9.9~12.h12.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2038");
  script_cve_id("CVE-2022-3554", "CVE-2022-3555");
  script_tag(name:"creation_date", value:"2023-06-07 04:14:30 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for libX11 (EulerOS-SA-2023-2038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2038");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2038");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libX11' package(s) announced via the EulerOS-SA-2023-2038 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in X.org libX11 and classified as problematic. This issue affects the function _XFreeX11XCBStructure of the file xcb_disp.c. The manipulation of the argument dpy leads to memory leak. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211055.(CVE-2022-3555)

A vulnerability has been found in X.org libX11 and classified as problematic. This vulnerability affects the function _XimRegisterIMInstantiateCallback of the file modules/im/ximcp/imsClbk.c. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211054 is the identifier assigned to this vulnerability.(CVE-2022-3554)");

  script_tag(name:"affected", value:"'libX11' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

if(release == "EULEROSVIRT-2.11.1") {

  if(!isnull(res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.7.2~2.h3.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
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
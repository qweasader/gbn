# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2580");
  script_cve_id("CVE-2014-0250", "CVE-2014-0791", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839", "CVE-2018-1000852");
  script_tag(name:"creation_date", value:"2020-01-23 13:07:16 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-25 15:20:55 +0000 (Fri, 25 May 2018)");

  script_name("Huawei EulerOS: Security Advisory for freerdp (EulerOS-SA-2019-2580)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2580");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2580");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'freerdp' package(s) announced via the EulerOS-SA-2019-2580 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable code execution vulnerability exists in the RDP receive functionality of FreeRDP 2.0.0-beta1+android11. A specially crafted server response can cause an out-of-bounds write resulting in an exploitable condition. An attacker can compromise the server or use a man in the middle to trigger this vulnerability.(CVE-2017-2835)

An exploitable denial of service vulnerability exists within the handling of challenge packets in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2838)

An exploitable denial of service vulnerability exists within the handling of challenge packets in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2839)

An exploitable denial of service vulnerability exists within the handling of security data in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2837)

An exploitable denial of service vulnerability exists within the reading of proprietary server certificates in FreeRDP 2.0.0-beta1+android11. A specially crafted challenge packet can cause the program termination leading to a denial of service condition. An attacker can compromise the server or use man in the middle to trigger this vulnerability.(CVE-2017-2836)

FreeRDP FreeRDP 2.0.0-rc3 released version before commit 205c612820dac644d665b5bb1cdf437dc5ca01e3 contains a Other/Unknown vulnerability in channels/drdynvc/client/drdynvc_main.c, drdynvc_process_capability_request that can result in The RDP server can read the client's memory.. This attack appear to be exploitable via RDPClient must connect the rdp server with echo option. This vulnerability appears to have been fixed in after commit 205c612820dac644d665b5bb1cdf437dc5ca01e3.(CVE-2018-1000852)

Integer overflow in the license_read_scope_list function in libfreerdp/core/license.c in FreeRDP through 1.0.2 allows remote RDP servers to cause a denial of service (application crash) or possibly have unspecified other impact via a large ScopeCount value in a Scope List in a Server License Request packet.(CVE-2014-0791)

Multiple integer overflows in client/X11/xf_graphics.c in FreeRDP allow remote attackers to have an unspecified impact via the width and height to the (1) xf_Pointer_New or (2) xf_Bitmap_Decompress function, which causes an incorrect amount of memory to be allocated.(CVE-2014-0250)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.2~6.1.h4", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~1.0.2~6.1.h4", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-plugins", rpm:"freerdp-plugins~1.0.2~6.1.h4", rls:"EULEROS-2.0SP3"))) {
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

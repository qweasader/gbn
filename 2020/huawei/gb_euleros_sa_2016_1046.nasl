# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1046");
  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5261", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2020-01-23 10:40:35 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Huawei EulerOS: Security Advisory for firefox (EulerOS-SA-2016-1046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2016-1046");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1046");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'firefox' package(s) announced via the EulerOS-SA-2016-1046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox before 48.0 allows remote attackers to obtain sensitive information about the previously retrieved page via Resource Timing API calls.(CVE-2016-5250)

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via unknown vectors.(CVE-2016-5257)

Integer overflow in the WebSocketChannel class in the WebSockets subsystem in Mozilla Firefox before 48.0 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted packets that trigger incorrect buffer-resize operations during buffering.(CVE-2016-5261)

Heap-based buffer overflow in the nsCaseTransformTextRunFactory::TransformString function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to cause a denial of service (boolean out-of-bounds write) or possibly have unspecified other impact via Unicode characters that are mishandled during text conversion.(CVE-2016-5270)

The nsImageGeometryMixin class in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 does not properly perform a cast of an unspecified variable during handling of INPUT elements, which allows remote attackers to execute arbitrary code via a crafted web site.(CVE-2016-5272)

Use-after-free vulnerability in the nsFrameManager::CaptureFrameState function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to execute arbitrary code by leveraging improper interaction between restyling and the Web Animations model implementation.(CVE-2016-5274)

Use-after-free vulnerability in the mozilla::a11y::DocAccessible::ProcessInvalidationList function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) via an aria-owns attribute.(CVE-2016-5276)

Use-after-free vulnerability in the nsRefreshDriver::Tick function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to execute arbitrary code or cause a denial of service (heap memory corruption) by leveraging improper interaction between timeline destruction and the Web Animations model implementation.(CVE-2016-5277)

Heap-based buffer overflow in the nsBMPEncoder::AddImageFrame function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to execute arbitrary code via a crafted image data that is mishandled during the encoding of an image frame to an image.(CVE-2016-5278)

Use-after-free vulnerability in the mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap function in Mozilla Firefox before 49.0 and Firefox ESR 45.x before 45.4 allows remote attackers to execute arbitrary code via bidirectional ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Huawei EulerOS V2.0SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.4.0~1", rls:"EULEROS-2.0SP1"))) {
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

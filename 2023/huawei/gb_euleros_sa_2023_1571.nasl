# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1571");
  script_cve_id("CVE-2022-43551", "CVE-2022-43552");
  script_tag(name:"creation_date", value:"2023-03-23 09:39:24 +0000 (Thu, 23 Mar 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 21:26:27 +0000 (Wed, 04 Jan 2023)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2023-1571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1571");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-1571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2023-1571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in curl. In this issue, curl can be asked to tunnel all protocols virtually it supports through an HTTP proxy. HTTP proxies can deny these tunnel operations using an appropriate HTTP error response code. When getting denied to tunnel the specific SMB or TELNET protocols, curl can use a heap-allocated struct after it has been freed and shut down the code path in its transfer.(CVE-2022-43552)

A vulnerability was found in curl. The issue can occur when curl's HSTS check is bypassed to trick it to keep using HTTP. Using its HSTS support, curl can be instructed to use HTTPS instead of an insecure clear-text HTTP step even when providing HTTP in the URL. Suppose the hostname in the given URL first uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion. In that case, it can bypass the HSTS mechanism using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop (U+002E). Then in a subsequent request, it does not detect the HSTS state and makes a clear text transfer. Because it would store the information, IDN encoded but looked for it as IDN decoded.(CVE-2022-43551)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.79.1~2.h9.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.79.1~2.h9.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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

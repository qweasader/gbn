# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2760");
  script_cve_id("CVE-2023-43804", "CVE-2023-45803", "CVE-2024-37891");
  script_tag(name:"creation_date", value:"2024-10-28 04:32:56 +0000 (Mon, 28 Oct 2024)");
  script_version("2024-10-29T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 13:44:00 +0000 (Tue, 10 Oct 2023)");

  script_name("Huawei EulerOS: Security Advisory for python-pip (EulerOS-SA-2024-2760)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2760");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2760");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-pip' package(s) announced via the EulerOS-SA-2024-2760 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs. Although this behavior is not specified in the section for redirects, it can be inferred by piecing together information from different sections and we have observed the behavior in other major HTTP client implementations like curl and web browsers. Because the vulnerability requires a previously trusted service to become compromised in order to have an impact on confidentiality we believe the exploitability of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised. This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve this issue. Users unable to update should disable redirects for services that aren't expecting to respond with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle 301, 302, and 303 redirects manually by stripping the HTTP request body.(CVE-2023-45803)

urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been patched in urllib3 version 1.26.17 or 2.0.5.(CVE-2023-43804)

 urllib3 is a user-friendly HTTP client library for Python. When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected. However, when sending HTTP requests *without* using urllib3's proxy support, it's possible to accidentally configure the `Proxy-Authorization` header even though it won't have any effect as the request is not using a forwarding proxy or a tunneling proxy. In those cases, urllib3 doesn't treat the `Proxy-Authorization` HTTP header as one carrying authentication material and thus doesn't strip the header on cross-origin redirects. Because this is a highly unlikely scenario, we believe the severity of this vulnerability is low for almost all users. Out of an abundance of caution urllib3 will ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-pip' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~21.3.1~2.h4.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~21.3.1~2.h4.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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

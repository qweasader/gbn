# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1411");
  script_cve_id("CVE-2023-38545", "CVE-2023-38546", "CVE-2023-46218");
  script_tag(name:"creation_date", value:"2024-03-21 04:24:36 +0000 (Thu, 21 Mar 2024)");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 13:24:03 +0000 (Wed, 25 Oct 2023)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2024-1411)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1411");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1411");
  script_xref(name:"URL", value:"https://curl.se/libcurl/c/curl_easy_duphandle.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2024-1411 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.When curl is asked to pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting done by curl itself, the maximum length that host name can be is 255 bytes.If the host name is detected to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due to this bug,the local variable that means 'let the host resolve the name' could get the wrong value during a slow SOCKS5 handshake, and contrary to the intention,copy the too long host name to the target buffer instead of copying just the resolved address there.The target buffer being a heap based buffer, and the host name coming from the URL that curl has been told to operate with.(CVE-2023-38545)

This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the specific series of conditions are met. libcurl performs transfers. In its API, an application creates 'easy handles' that are the individual handles for single transfers. libcurl provides a function call that duplicates en easy handle called [curl_easy_duphandle]([link moved to references]). If a transfer has cookies enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned version of the handle would instead store the file name as `none` (using the four ASCII letters, no quotes). Subsequent use of the cloned handle that does not explicitly set a source to load cookies from would then inadvertently load cookies from a file named `none` - if such a file exists and is readable in the current directory of the program using libcurl. And if using the correct file format of course.(CVE-2023-38546)

This flaw allows a malicious HTTP server to set 'super cookies' in curl that are then passed back to more origins than what is otherwise allowed or possible. This allows a site to set cookies that then would get sent to different and unrelated sites and domains.It could do this by exploiting a mixed case flaw in curl's function that verifies a given cookie domain against the Public Suffix List (PSL). For example a cookie could be set with `domain=co.UK` when the URL used a lower case hostname `curl.co.uk`, even though `co.uk` is listed as a PSL domain.(CVE-2023-46218)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.79.1~2.h26.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.79.1~2.h26.eulerosv2r11", rls:"EULEROSVIRT-2.11.1"))) {
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

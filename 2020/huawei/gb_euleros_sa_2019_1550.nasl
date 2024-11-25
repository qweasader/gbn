# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1550");
  script_cve_id("CVE-2013-2174", "CVE-2014-3707", "CVE-2015-3143", "CVE-2015-3148", "CVE-2016-5420", "CVE-2016-7167", "CVE-2016-8616", "CVE-2016-8619", "CVE-2017-1000100", "CVE-2017-1000254", "CVE-2018-1000007", "CVE-2018-1000301");
  script_tag(name:"creation_date", value:"2020-01-23 12:12:25 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:36:22 +0000 (Tue, 09 Oct 2018)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2019-1550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1550");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1550");
  script_xref(name:"URL", value:"https://github.com/curl/curl/commit/415d2e7cb7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2019-1550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"curl version curl 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content..(CVE-2018-1000301)

It was found that the libcurl library did not check the client certificate when choosing the TLS connection to reuse. An attacker could potentially use this flaw to hijack the authentication of the connection by leveraging a previously created connection with a different client certificate.(CVE-2016-5420)

It was discovered that libcurl could incorrectly reuse NTLM-authenticated connections for subsequent unauthenticated requests to the same host. If an application using libcurl established an NTLM-authenticated connection to a server, and sent subsequent unauthenticated requests to the same server, the unauthenticated requests could be sent over the NTLM-authenticated connection, appearing as if they were sent by the NTLM authenticated user.(CVE-2015-3143)

libcurl may read outside of a heap allocated buffer when doing FTP. When libcurl connects to an FTP server and successfully logs in (anonymous or not), it asks the server for the current directory with the `PWD` command. The server then responds with a 257 response containing the path, inside double quotes. The returned path name is then kept by libcurl for subsequent uses. Due to a flaw in the string parser for this directory name, a directory name passed like this but without a closing double quote would lead to libcurl not adding a trailing NUL byte to the buffer holding the name. When libcurl would then later access the string, it could read beyond the allocated heap buffer and crash or wrongly access data beyond the buffer, thinking it was part of the path. A malicious server could abuse this fact and effectively prevent libcurl-based clients to work with it - the PWD command is always issued on new FTP connections and the mistake has a high chance of causing a segfault. The simple fact that this has issue remained undiscovered for this long could suggest that malformed PWD responses are rare in benign servers. We are not aware of any exploit of this flaw. This bug was introduced in commit 415d2e7cb7([link moved to references]), March 2005. In libcurl version 7.56.0, the parser always zero terminates the string but also rejects it if not terminated properly with a final double quote.(CVE-2017-1000254)

It was discovered that libcurl could incorrectly reuse Negotiate authenticated HTTP connections for subsequent requests. If an application using libcurl established a Negotiate authenticated HTTP connection to a server and sent subsequent requests with different credentials, the connection could be re-used with the initial set of credentials instead of using the new ones.(CVE-2015-3148)

Heap-based buffer overflow in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~46.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~46.h10", rls:"EULEROSVIRT-3.0.1.0"))) {
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

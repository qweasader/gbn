# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2222");
  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2372", "CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376", "CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323");
  script_tag(name:"creation_date", value:"2020-01-23 12:41:00 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-30 01:59:00 +0000 (Thu, 30 Mar 2017)");

  script_name("Huawei EulerOS: Security Advisory for pidgin (EulerOS-SA-2019-2222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2222");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2222");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'pidgin' package(s) announced via the EulerOS-SA-2019-2222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability exists in the handling of the MXIT protocol Pidgin. Specially crafted data sent via the server could potentially result in a buffer overflow, potentially resulting in memory corruption. A malicious server or an unfiltered malicious user can send negative length values to trigger this vulnerability.(CVE-2016-2378)

A buffer overflow vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent from the server could potentially result in arbitrary code execution. A malicious server or an attacker who intercepts the network traffic can send an invalid size for a packet which will trigger a buffer overflow.(CVE-2016-2376)

An exploitable out-of-bounds read exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT contact information sent from the server can result in memory disclosure.(CVE-2016-2375)

An exploitable memory corruption vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT MultiMX message sent via the server can result in an out-of-bounds write leading to memory disclosure and code execution.(CVE-2016-2374)

A buffer overflow vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent by the server could potentially result in an out-of-bounds write of one byte. A malicious server can send a negative content-length in response to a HTTP request triggering the vulnerability.(CVE-2016-2377)

A denial of service vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in an out-of-bounds read. A malicious server or user can send an invalid mood to trigger this vulnerability.(CVE-2016-2373)

An out-of-bounds write vulnerability exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could cause memory corruption resulting in code execution.(CVE-2016-2371)

A directory traversal exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent from the server could potentially result in an overwrite of files. A malicious server or someone with access to the network traffic can provide an invalid filename for a splash image triggering the vulnerability.(CVE-2016-4323)

An information leak exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent to the server could potentially result in an out-of-bounds read. A user could be convinced to enter a particular string which would then get converted incorrectly and could lead to a potential out-of-bounds read.(CVE-2016-2380)

An information leak exists in the handling of the MXIT protocol in Pidgin. Specially crafted MXIT data sent via the server could potentially result in an out-of-bounds read. A malicious user, server, or man-in-the-middle attacker can send an invalid ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pidgin' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.10.11~7.h4.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884315");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2024-1546", "CVE-2024-1547", "CVE-2024-1553", "CVE-2024-1548", "CVE-2024-1549", "CVE-2024-1550", "CVE-2024-1551", "CVE-2024-1552");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:32:39 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for firefox (CESA-2024:0976)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0976");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-February/099230.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2024:0976 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards compliance, performance, and portability.

This Update upgrades Firefox to version 115.8.0 ESR.

Security Fix(es):

  * Mozilla: Out-of-bounds memory read in networking channels (CVE-2024-1546)

  * Mozilla: Alert dialog could have been spoofed on another site (CVE-2024-1547)

  * Mozilla: Memory safety bugs fixed in Firefox 123, Firefox ESR 115.8, and Thunderbird 115.8 (CVE-2024-1553)

  * Mozilla: Fullscreen Notification could have been hidden by select element (CVE-2024-1548)

  * Mozilla: Custom cursor could obscure the permission dialog (CVE-2024-1549)

  * Mozilla: Mouse cursor re-positioned unexpectedly could have led to unintended permission grants (CVE-2024-1550)

  * Mozilla: Multipart HTTP Responses would accept the Set-Cookie header in response parts (CVE-2024-1551)

  * Mozilla: Incorrect code generation on 32-bit ARM devices (CVE-2024-1552)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'firefox' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~115.8.0~1.el7.centos", rls:"CentOS7"))) {
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
# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884329");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:33:29 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2024:0600)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0600");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-February/099221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2024:0600 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards compliance, performance, and portability.

This Update upgrades Firefox to version 115.7.0 ESR.

Security Fix(es):

  * Mozilla: Out of bounds write in ANGLE (CVE-2024-0741)

  * Mozilla: Failure to update user input timestamp (CVE-2024-0742)

  * Mozilla: Crash when listing printers on Linux (CVE-2024-0746)

  * Mozilla: Bypass of Content Security Policy when directive unsafe-inline was set (CVE-2024-0747)

  * Mozilla: Phishing site popup could show local origin in address bar (CVE-2024-0749)

  * Mozilla: Potential permissions request bypass via clickjacking (CVE-2024-0750)

  * Mozilla: Privilege escalation through devtools (CVE-2024-0751)

  * Mozilla: HSTS policy on subdomain could bypass policy of upper domain (CVE-2024-0753)

  * Mozilla: Memory safety bugs fixed in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7 (CVE-2024-0755)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~115.7.0~1.el7.centos", rls:"CentOS7"))) {
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
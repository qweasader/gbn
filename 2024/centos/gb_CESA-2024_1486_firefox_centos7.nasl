# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884337");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2023-5388", "CVE-2024-0743", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2616", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614", "CVE-2024-29944");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:27 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-04-04 01:06:40 +0000 (Thu, 04 Apr 2024)");
  script_name("CentOS: Security Advisory for firefox (CESA-2024:1486)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:1486");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-April/099237.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2024:1486 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards compliance, performance, and portability.

This Update upgrades Firefox to version 115.9.1 ESR.

Security Fix(es):

  * nss: timing attack against RSA decryption (CVE-2023-5388)

  * Mozilla: Crash in NSS TLS method (CVE-2024-0743)

  * Mozilla: JIT code failed to save return registers on Armv7-A (CVE-2024-2607)

  * Mozilla: Integer overflow could have led to out of bounds write (CVE-2024-2608)

  * Mozilla: Improve handling of out-of-memory conditions in ICU (CVE-2024-2616)

  * Mozilla: Improper handling of html and body tags enabled CSP nonce leakage (CVE-2024-2610)

  * Mozilla: Clickjacking vulnerability could have led to a user accidentally granting permissions (CVE-2024-2611)

  * Mozilla: Self referencing object could have potentially led to a use-after-free (CVE-2024-2612)

  * Mozilla: Memory safety bugs fixed in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9 (CVE-2024-2614)

  * Mozilla: Privileged JavaScript Execution via Event Handlers (CVE-2024-29944)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~115.9.1~1.el7.centos", rls:"CentOS7"))) {
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
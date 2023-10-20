# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0218");
  script_cve_id("CVE-2015-3044", "CVE-2015-3077", "CVE-2015-3078", "CVE-2015-3079", "CVE-2015-3080", "CVE-2015-3081", "CVE-2015-3082", "CVE-2015-3083", "CVE-2015-3084", "CVE-2015-3085", "CVE-2015-3086", "CVE-2015-3087", "CVE-2015-3088", "CVE-2015-3089", "CVE-2015-3090", "CVE-2015-3091", "CVE-2015-3092", "CVE-2015-3093");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0218)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0218");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0218.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15916");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0218 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.460 contains fixes to critical security
vulnerabilities found in earlier versions that could cause a crash and
potentially allow an attacker to take control of the affected system.

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2015-3078, CVE-2015-3089, CVE-2015-3090,
CVE-2015-3093).

This update resolves a heap overflow vulnerability that could lead to code
execution (CVE-2015-3088).

This update resolves a time-of-check time-of-use (TOCTOU) race condition
that could be exploited to bypass Protected Mode in Internet Explorer
(CVE-2015-3081).

This update resolves validation bypass issues that could be exploited to
write arbitrary data to the file system under user permissions
(CVE-2015-3082, CVE-2015-3083, CVE-2015-3085).

This update resolves an integer overflow vulnerability that could lead to
code execution (CVE-2015-3087).

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-3077, CVE-2015-3084, CVE-2015-3086).

This update resolves a use-after-free vulnerability that could lead to code
execution (CVE-2015-3080).

This update resolves memory leak vulnerabilities that could be used to
bypass ASLR (CVE-2015-3091, CVE-2015-3092).

This update resolves a security bypass vulnerability that could lead to
information disclosure (CVE-2015-3079), and provides additional hardening
to protect against CVE-2015-3044.");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.460~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.460~1.mga4.nonfree", rls:"MAGEIA4"))) {
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

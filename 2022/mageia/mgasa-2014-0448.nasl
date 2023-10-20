# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0448");
  script_cve_id("CVE-2014-0558", "CVE-2014-0564", "CVE-2014-0569", "CVE-2014-0573", "CVE-2014-0574", "CVE-2014-0576", "CVE-2014-0577", "CVE-2014-0581", "CVE-2014-0582", "CVE-2014-0583", "CVE-2014-0584", "CVE-2014-0585", "CVE-2014-0586", "CVE-2014-0588", "CVE-2014-0589", "CVE-2014-0590", "CVE-2014-8437", "CVE-2014-8438", "CVE-2014-8440", "CVE-2014-8441", "CVE-2014-8442");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0448)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0448");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0448.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14506");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-22.html");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-24.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2014-0448 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.418 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2014-0558, CVE-2014-0564, CVE-2014-0576, CVE-2014-0581,
CVE-2014-8440, CVE-2014-8441).

This update resolves an integer overflow vulnerability that could lead to
code execution (CVE-2014-0569).

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2014-0573, CVE-2014-0588, CVE-2014-8438).

This update resolves a double free vulnerability that could lead to code
execution (CVE-2014-0574).

This update resolves type confusion vulnerabilities that could lead to code
execution (CVE-2014-0577, CVE-2014-0584, CVE-2014-0585, CVE-2014-0586,
CVE-2014-0590).

This update resolves heap buffer overflow vulnerabilities that could lead
to code execution (CVE-2014-0582, CVE-2014-0589).

This update resolves an information disclosure vulnerability that could be
exploited to disclose session tokens (CVE-2014-8437).

This update resolves a heap buffer overflow vulnerability that could be
exploited to perform privilege escalation from low to medium integrity
level (CVE-2014-0583).

This update resolves a permission issue that could be exploited to perform
privilege escalation from low to medium integrity level (CVE-2014-8442).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.418~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.418~1.mga3.nonfree", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.418~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.418~1.mga4.nonfree", rls:"MAGEIA4"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0207");
  script_cve_id("CVE-2023-45733", "CVE-2023-45745", "CVE-2023-46103");
  script_tag(name:"creation_date", value:"2024-06-04 04:11:12 +0000 (Tue, 04 Jun 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0207)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0207");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0207.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33251");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20240514");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6797-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2024-0207 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package fixes security vulnerabilities:
Hardware logic contains race conditions in some Intel(R) Processors may
allow an authenticated user to potentially enable partial information
disclosure via local access. (CVE-2023-45733)
Sequence of processor instructions leads to unexpected behavior in
Intel(R) Core(TM) Ultra Processors may allow an authenticated user to
potentially enable denial of service via local access. (CVE-2023-46103)
Improper input validation in some Intel(R) TDX module software before
version 1.5.05.46.698 may allow a privileged user to potentially enable
escalation of privilege via local access. (CVE-2023-45745)");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20240514~1.mga9.nonfree", rls:"MAGEIA9"))) {
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

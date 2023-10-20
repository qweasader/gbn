# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0064");
  script_cve_id("CVE-2021-0127", "CVE-2021-0145", "CVE-2021-0146", "CVE-2021-33120");
  script_tag(name:"creation_date", value:"2022-02-16 03:20:56 +0000 (Wed, 16 Feb 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-15 17:50:00 +0000 (Tue, 15 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0064");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0064.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30037");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20220207");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00528.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00532.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00561.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00589.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2022-0064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated microcodes for Intel processors, fixing various functional
issues, and at least the following security issues:

Insufficient control flow management in some Intel(R) Processors may allow
an authenticated user to potentially enable a denial of service via local
access (CVE-2021-0127 / SA-00532).

Improper initialization of shared resources in some Intel(R) Processors may
allow an authenticated user to potentially enable information disclosure
via local access (CVE-2021-0145 / SA-00561).

Hardware allows activation of test or debug logic at runtime for some
Intel(R) processors which may allow an unauthenticated user to potentially
enable escalation of privilege via physical access
(CVE-2021-0146 / SA-00528).

Out of bounds read under complex microarchitectural condition in memory
subsystem for some Intel Atom(R) Processors may allow authenticated user
to potentially enable information disclosure or cause denial of service
via network access (CVE-2021-33120 / SA-00589)

For info about the other fixes in this update, see the github reference.");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20220207~1.mga8.nonfree", rls:"MAGEIA8"))) {
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

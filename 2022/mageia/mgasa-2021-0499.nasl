# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0499");
  script_cve_id("CVE-2021-28116");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-13 00:19:28 +0000 (Sat, 13 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0499)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0499");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0499.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29524");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/commit/3896e584d7eeb321d7becbcedec872ffa868dd87");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/commit/874e8b4ca0342a1c399ddadc1cf6998590fa46a6");
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-rgf3-9v3p-qp82");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2021-0499 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated squid packages fix security vulnerability:

Squid through 4.14 and 5.x through 5.0.5, in some configurations, allows
information disclosure because of an out-of-bounds read in WCCP protocol
data. This can be leveraged as part of a chain for remote code execution
as nobody (CVE-2021-28116).

Squid is updated to 4.17 that fixes this issue and other bugs.");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.17~1.mga8", rls:"MAGEIA8"))) {
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

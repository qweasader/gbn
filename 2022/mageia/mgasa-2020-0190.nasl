# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0190");
  script_cve_id("CVE-2020-11722");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-13 16:52:12 +0000 (Mon, 13 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0190");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0190.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26552");
  script_xref(name:"URL", value:"https://github.com/crawl/crawl/commits/a250c9d538d3db384407f7e61470e8ec65ad5b83");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2020-04/msg00113.html");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/crawl/crawl/0.24.1/crawl-ref/docs/changelog.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crawl' package(s) announced via the MGASA-2020-0190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated crawl packages fix security vulnerability

crawl 0.24.0 and earlier are subject to possible remote code evaluation
with lua loadstring (CVE-2020-11722).

This update fixes it, also updating crawl from version 0.23.2 to 0.24.1,
with the following main gameplay changes:

* Vampire species simplified
* Thrown weapons streamlined
* Fedhas reimagined
* Sif Muna reworked");

  script_tag(name:"affected", value:"'crawl' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"crawl", rpm:"crawl~0.24.1~2.ga250c9d538.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-common-data", rpm:"crawl-common-data~0.24.1~2.ga250c9d538.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-console", rpm:"crawl-console~0.24.1~2.ga250c9d538.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-tiles", rpm:"crawl-tiles~0.24.1~2.ga250c9d538.1.mga7", rls:"MAGEIA7"))) {
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

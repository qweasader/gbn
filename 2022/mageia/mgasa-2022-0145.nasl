# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0145");
  script_cve_id("CVE-2022-28201", "CVE-2022-28202", "CVE-2022-28203", "CVE-2022-28204");
  script_tag(name:"creation_date", value:"2022-04-20 04:37:20 +0000 (Wed, 20 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:11:43 +0000 (Wed, 21 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0145");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0145.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30231");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/YJNXKPV5Z56NSUQ4G3SXPDUIZG5EQ7UR/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2022-0145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Title::newMainPage() goes into an infinite recursion loop if it points to a
local interwiki (CVE-2022-28201).

Messages widthheight/widthheightpage/nbytes not escaped when used in galleries
or Special:RevisionDelete (CVE-2022-28202).

Requesting Special:NewFiles on a wiki with many file uploads with actor as a
condition can result in a DoS (CVE-2022-28203).

Special:WhatLinksHere can result in a DoS when a page is used on a extremely
large number of other pages (CVE-2022-28204).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.6~1.mga8", rls:"MAGEIA8"))) {
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

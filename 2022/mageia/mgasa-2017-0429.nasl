# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0429");
  script_cve_id("CVE-2017-8808", "CVE-2017-8809", "CVE-2017-8810", "CVE-2017-8811", "CVE-2017-8812", "CVE-2017-8814", "CVE-2017-8815", "CVE-2017-9841");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:39:00 +0000 (Tue, 14 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2017-0429)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0429");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0429.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22038");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2017-0429 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XSS when $wgShowExceptionDetails = false and browser sends non-standard
url escaping (CVE-2017-8808).

Reflected File Download from api.php (CVE-2017-8809).

On private wikis, login form shouldn't distinguish between login failure
due to bad username and bad password (CVE-2017-8810).

It's possible to mangle HTML via raw message parameter expansion
(CVE-2017-8811).

The id attribute on headlines allow raw > (CVE-2017-8812).

Language converter can be tricked into replacing text inside tags by
adding a lot of junk after the rule definition (CVE-2017-8814).

Language converter: unsafe attribute injection via glossary rules
(CVE-2017-8815).

composer.json has require-dev versions of PHPUnit with known security
issues (CVE-2017-9841).

Note that MediaWiki 1.23.x on Mageia 5 is no longer supported. Those
using the mediawiki package on Mageia 5 should upgrade to Mageia 6.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.27.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.27.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.27.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.27.4~1.mga6", rls:"MAGEIA6"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0110");
  script_cve_id("CVE-2017-0361", "CVE-2017-0362", "CVE-2017-0363", "CVE-2017-0364", "CVE-2017-0365", "CVE-2017-0366", "CVE-2017-0368", "CVE-2017-0369", "CVE-2017-0370");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-15 13:21:28 +0000 (Tue, 15 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0110)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0110");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0110.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20654");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-April/000207.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2017-0110 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"API parameters may now be marked as 'sensitive' to keep their values out
of the logs (CVE-2017-0361).

'Mark all pages visited' on the watchlist now requires a CSRF token
(CVE-2017-0362).

Special:UserLogin and Special:Search allow redirect to interwiki links
(CVE-2017-0363, CVE-2017-0364).

XSS in SearchHighlighter::highlightText() when
$wgAdvancedSearchHighlighting is true (CVE-2017-0365).

SVG filter evasion using default attribute values in DTD declaration
(CVE-2017-0366).

Escape content model/format url parameter in message (CVE-2017-0368).

Sysops can undelete pages, although the page is protected against it
(CVE-2017-0369).

Spam blacklist ineffective on encoded URLs inside file inclusion syntax's
link parameter (CVE-2017-0370).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.16~1.mga5", rls:"MAGEIA5"))) {
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

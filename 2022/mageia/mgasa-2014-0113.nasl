# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0113");
  script_cve_id("CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6472", "CVE-2014-1610");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 18:32:00 +0000 (Thu, 30 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0113)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0113");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0113.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12337");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000138.html");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000140.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-January/127027.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-February/127948.html");
  script_xref(name:"URL", value:"http://www.mediawiki.org/wiki/Extension:GraphViz");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki, mediawiki-ldapauthentication, mediawiki-math' package(s) announced via the MGASA-2014-0113 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki user Michael M reported that the fix for CVE-2013-4568 allowed
insertion of escaped CSS values which could pass the CSS validation checks,
resulting in XSS (CVE-2013-6451).

Chris from RationalWiki reported that SVG files could be uploaded that
include external stylesheets, which could lead to XSS when an XSL was used
to include JavaScript (CVE-2013-6452).

During internal review, it was discovered that MediaWiki's SVG sanitization
could be bypassed when the XML was considered invalid (CVE-2013-6453).

During internal review, it was discovered that MediaWiki displayed some
information about deleted pages in the log API, enhanced RecentChanges, and
user watchlists (CVE-2013-6472).

Netanel Rubin from Check Point discovered a remote code execution
vulnerability in MediaWiki's thumbnail generation for DjVu files. Internal
review also discovered similar logic in the PdfHandler extension, which
could be exploited in a similar way (CVE-2014-1610).

MediaWiki has been updated to version 1.22.2, which fixes these issues, as
well as several others.

Also, the mediawiki-ldapauthentication and mediawiki-math extensions have
been updated to newer versions that are compatible with MediaWiki 1.22.

Additionally, the mediawiki-graphviz extension has been obsoleted, due to
the fact that it is unmaintained upstream and is vulnerable to cross-site
scripting attacks.

Note: if you were using the 'instances' feature in these packages to
support multiple wiki instances, this feature has now been removed. You
will need to maintain separate wiki instances manually.");

  script_tag(name:"affected", value:"'mediawiki, mediawiki-ldapauthentication, mediawiki-math' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.22.2~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-ldapauthentication", rpm:"mediawiki-ldapauthentication~2.0f~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-math", rpm:"mediawiki-math~1.1~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.22.2~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.22.2~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.22.2~1.1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.22.2~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-ldapauthentication", rpm:"mediawiki-ldapauthentication~2.0f~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-math", rpm:"mediawiki-math~1.1~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.22.2~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.22.2~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.22.2~1.1.mga4", rls:"MAGEIA4"))) {
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

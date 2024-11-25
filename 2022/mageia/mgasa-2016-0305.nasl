# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0305");
  script_cve_id("CVE-2016-6331", "CVE-2016-6332", "CVE-2016-6333", "CVE-2016-6334", "CVE-2016-6335", "CVE-2016-6336");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-24 20:24:12 +0000 (Mon, 24 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0305)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0305");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0305.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19252");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2016-August/000195.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2016-0305 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Check read permission when loading page content in ApiParse
(CVE-2016-6331)

Make blocks log users out if $wgBlockDisablesLogin is true (CVE-2016-6332)

Make $wgBlockDisablesLogin also restrict logged in permissions
(CVE-2016-6332)

Require login to preview user CSS pages (CVE-2016-6333)

Escape '<' and ']]>' in inline <style> blocks (CVE-2016-6333)

XSS in unclosed internal links (CVE-2016-6334)

API: Generate head items in the context of the given title (CVE-2016-6335)

Do not allow undeleting a revision deleted file if it is the top file
(CVE-2016-6336)

The mediawiki package has been updated to version 1.23.15, which contains
the above fixes.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.15~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.15~1.mga5", rls:"MAGEIA5"))) {
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

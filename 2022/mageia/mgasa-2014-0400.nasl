# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0400");
  script_cve_id("CVE-2014-7199", "CVE-2014-7295");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0400)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0400");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0400.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14182");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-October/000163.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-September/000161.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3036");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3046");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2014-0400 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mediawiki packages fix security vulnerability:

MediaWiki before 1.23.4 is vulnerable to cross-site scripting due to
JavaScript injection via CSS in uploaded SVG files (CVE-2014-7199).

MediaWiki before 1.23.5 is vulnerable to cross-site scripting due to
JavaScript injection via user-specificed CSS in certain special pages
(CVE-2014-7295).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.5~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.5~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.5~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.5~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.5~1.mga4", rls:"MAGEIA4"))) {
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

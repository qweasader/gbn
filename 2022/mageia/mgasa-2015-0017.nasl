# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0017");
  script_cve_id("CVE-2014-5032", "CVE-2014-8360", "CVE-2014-9258");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0017");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0017.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14933");
  script_xref(name:"URL", value:"http://www.glpi-project.org/spip.php?page=annonce&id_breve=326&lang=en");
  script_xref(name:"URL", value:"http://www.glpi-project.org/spip.php?page=annonce&id_breve=330&lang=en");
  script_xref(name:"URL", value:"http://www.glpi-project.org/spip.php?page=annonce&id_breve=334&lang=en");
  script_xref(name:"URL", value:"http://tlk.tuxfamily.org/doku.php?id=writeup:cve-2014-8360");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/147296.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glpi' package(s) announced via the MGASA-2015-0017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glpi package fixes security vulnerabilities:

Due to a bug in GLPI before 0.84.7, a user without access to cost information
can in fact see the information when selecting cost as a search criteria
(CVE-2014-5032).

An issue in GLPI before 0.84.8 may allow arbitrary local files to be included
by PHP through an autoload function (CVE-2014-8360).

SQL injection vulnerability in ajax/getDropdownValue.php in GLPI before 0.85.1
allows remote authenticated users to execute arbitrary SQL commands via the
condition parameter (CVE-2014-9258).");

  script_tag(name:"affected", value:"'glpi' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"glpi", rpm:"glpi~0.84.3~1.2.mga4", rls:"MAGEIA4"))) {
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

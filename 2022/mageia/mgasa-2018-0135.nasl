# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0135");
  script_cve_id("CVE-2017-11183", "CVE-2017-11184", "CVE-2017-11329", "CVE-2017-11474", "CVE-2017-11475");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-21 16:34:00 +0000 (Fri, 21 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0135");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0135.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21331");
  script_xref(name:"URL", value:"http://glpi-project.org/spip.php?page=annonce&id_breve=370&lang=en");
  script_xref(name:"URL", value:"http://glpi-project.org/spip.php?page=annonce&id_breve=373&lang=en");
  script_xref(name:"URL", value:"http://glpi-project.org/spip.php?page=annonce&id_breve=376&lang=en");
  script_xref(name:"URL", value:"http://glpi-project.org/spip.php?page=annonce&id_breve=378&lang=en");
  script_xref(name:"URL", value:"http://glpi-project.org/spip.php?page=annonce&id_breve=379&lang=en");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glpi, php-zetacomponents-base' package(s) announced via the MGASA-2018-0135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The glpi package has been updated to version 9.1.6, which fixes several
security issues and other bugs. See the upstream release announcements
for details.

An issue in the php-zetacomponents-base package which prevented GLPI from
working has also been fixed.");

  script_tag(name:"affected", value:"'glpi, php-zetacomponents-base' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"glpi", rpm:"glpi~9.1.6~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-zetacomponents-base", rpm:"php-zetacomponents-base~1.9~1.1.mga6", rls:"MAGEIA6"))) {
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

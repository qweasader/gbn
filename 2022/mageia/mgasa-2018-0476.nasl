# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0476");
  script_cve_id("CVE-2018-19516");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-18 13:17:00 +0000 (Wed, 18 Mar 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0476)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0476");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0476.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23923");
  script_xref(name:"URL", value:"https://www.kde.org/info/security/advisory-20181128-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'messagelib' package(s) announced via the MGASA-2018-0476 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Some HTML emails can trick messagelib into opening a new browser window
when displaying said email as HTML. This happens even if the option to
allow the HTML emails to access remote servers is disabled in KMail
settings. This means that the owners of the servers referred in the
email can see in their access logs your IP address (CVE-2018-19516).");

  script_tag(name:"affected", value:"'messagelib' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecomposer5", rpm:"lib64kf5messagecomposer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecore5", rpm:"lib64kf5messagecore5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelib-devel", rpm:"lib64kf5messagelib-devel~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelist5", rpm:"lib64kf5messagelist5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messageviewer5", rpm:"lib64kf5messageviewer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5mimetreeparser5", rpm:"lib64kf5mimetreeparser5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5templateparser5", rpm:"lib64kf5templateparser5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5webengineviewer5", rpm:"lib64kf5webengineviewer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecomposer5", rpm:"libkf5messagecomposer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecore5", rpm:"libkf5messagecore5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelib-devel", rpm:"libkf5messagelib-devel~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelist5", rpm:"libkf5messagelist5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messageviewer5", rpm:"libkf5messageviewer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5mimetreeparser5", rpm:"libkf5mimetreeparser5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5templateparser5", rpm:"libkf5templateparser5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5webengineviewer5", rpm:"libkf5webengineviewer5~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messagelib", rpm:"messagelib~17.12.2~1.1.mga6", rls:"MAGEIA6"))) {
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

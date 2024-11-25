# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0240");
  script_cve_id("CVE-2014-0190");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0240");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0240.html");
  script_xref(name:"URL", value:"http://blog.qt.digia.com/blog/2014/04/24/qt-4-8-6-released/");
  script_xref(name:"URL", value:"http://lists.qt-project.org/pipermail/announce/2014-April/000045.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13276");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132395.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4' package(s) announced via the MGASA-2014-0240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw was found in QGIFFormat::fillRect in QtGui.
If an application using the qt-x11 libraries opened a malicious GIF file with
invalid width and height values, it could cause the application to crash
(CVE-2014-0190).

Qt4 has been patched to correct this flaw and has been updated to version
4.8.6, which fixes several other bugs.");

  script_tag(name:"affected", value:"'qt4' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qt3support4", rpm:"lib64qt3support4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt4-devel", rpm:"lib64qt4-devel~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtclucene4", rpm:"lib64qtclucene4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtcore4", rpm:"lib64qtcore4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdbus4", rpm:"lib64qtdbus4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdeclarative4", rpm:"lib64qtdeclarative4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtdesigner4", rpm:"lib64qtdesigner4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtgui4", rpm:"lib64qtgui4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qthelp4", rpm:"lib64qthelp4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtmultimedia4", rpm:"lib64qtmultimedia4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtnetwork4", rpm:"lib64qtnetwork4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtopengl4", rpm:"lib64qtopengl4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscript4", rpm:"lib64qtscript4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtscripttools4", rpm:"lib64qtscripttools4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsql4", rpm:"lib64qtsql4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtsvg4", rpm:"lib64qtsvg4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qttest4", rpm:"lib64qttest4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxml4", rpm:"lib64qtxml4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qtxmlpatterns4", rpm:"lib64qtxmlpatterns4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt3support4", rpm:"libqt3support4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-devel", rpm:"libqt4-devel~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtclucene4", rpm:"libqtclucene4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtcore4", rpm:"libqtcore4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdbus4", rpm:"libqtdbus4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdeclarative4", rpm:"libqtdeclarative4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtdesigner4", rpm:"libqtdesigner4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtgui4", rpm:"libqtgui4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqthelp4", rpm:"libqthelp4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtmultimedia4", rpm:"libqtmultimedia4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtnetwork4", rpm:"libqtnetwork4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtopengl4", rpm:"libqtopengl4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscript4", rpm:"libqtscript4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtscripttools4", rpm:"libqtscripttools4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsql4", rpm:"libqtsql4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtsvg4", rpm:"libqtsvg4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqttest4", rpm:"libqttest4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxml4", rpm:"libqtxml4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqtxmlpatterns4", rpm:"libqtxmlpatterns4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-accessibility-plugin", rpm:"qt4-accessibility-plugin~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-assistant", rpm:"qt4-assistant~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-common", rpm:"qt4-common~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-database-plugin-mysql", rpm:"qt4-database-plugin-mysql~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-database-plugin-pgsql", rpm:"qt4-database-plugin-pgsql~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-database-plugin-sqlite", rpm:"qt4-database-plugin-sqlite~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-database-plugin-tds", rpm:"qt4-database-plugin-tds~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-demos", rpm:"qt4-demos~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer", rpm:"qt4-designer~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer-plugin-qt3support", rpm:"qt4-designer-plugin-qt3support~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-designer-plugin-webkit", rpm:"qt4-designer-plugin-webkit~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-devel-private", rpm:"qt4-devel-private~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-examples", rpm:"qt4-examples~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-graphicssystems-plugin", rpm:"qt4-graphicssystems-plugin~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-linguist", rpm:"qt4-linguist~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qdoc3", rpm:"qt4-qdoc3~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qmlviewer", rpm:"qt4-qmlviewer~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtconfig", rpm:"qt4-qtconfig~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qtdbus", rpm:"qt4-qtdbus~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-qvfb", rpm:"qt4-qvfb~4.8.6~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-xmlpatterns", rpm:"qt4-xmlpatterns~4.8.6~1.mga3", rls:"MAGEIA3"))) {
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

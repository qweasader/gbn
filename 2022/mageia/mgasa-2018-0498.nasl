# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0498");
  script_cve_id("CVE-2018-19149");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0498)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0498");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0498.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24073");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3837-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the MGASA-2018-0498 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Poppler before 0.70.0 has a NULL pointer dereference in
_poppler_attachment_new when called from
poppler_annot_file_attachment_get_attachment. (CVE-2018-19149)");

  script_tag(name:"affected", value:"'poppler' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp-devel", rpm:"lib64poppler-cpp-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-cpp0", rpm:"lib64poppler-cpp0~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-gir0.18", rpm:"lib64poppler-gir0.18~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-glib8", rpm:"lib64poppler-glib8~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt4_4", rpm:"lib64poppler-qt4_4~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5-devel", rpm:"lib64poppler-qt5-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler-qt5_1", rpm:"lib64poppler-qt5_1~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64poppler66", rpm:"lib64poppler66~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp-devel", rpm:"libpoppler-cpp-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-gir0.18", rpm:"libpoppler-gir0.18~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4_4", rpm:"libpoppler-qt4_4~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5_1", rpm:"libpoppler-qt5_1~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler66", rpm:"libpoppler66~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.52.0~3.10.mga6", rls:"MAGEIA6"))) {
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

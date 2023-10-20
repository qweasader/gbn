# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1999.1");
  script_cve_id("CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775", "CVE-2017-9776");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 17:27:00 +0000 (Tue, 12 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1999-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1999-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171999-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2017:1999-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:
Security issues fixed:
- CVE-2017-9775: DoS stack buffer overflow in GfxState.cc in pdftocairo
 via a crafted PDF document (bsc#1045719)
- CVE-2017-9776: DoS integer overflow leading to heap buffer overflow in
 JBIG2Stream.cc via a crafted PDF document (bsc#1045721)
- CVE-2017-7515: Stack exhaustion due to infinite recursive call in
 pdfunite (bsc#1043088)
- CVE-2017-7511: Null pointer dereference in pdfunite via crafted
 documents (bsc#1041783)
- CVE-2017-9406: Memory leak in the gmalloc function in gmem.cc
 (bsc#1042803)
- CVE-2017-9408: Memory leak in the Object::initArray function
 (bsc#1042802)");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt-debugsource", rpm:"poppler-qt-debugsource~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt-debugsource", rpm:"poppler-qt-debugsource~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~16.5.1", rls:"SLES12.0SP3"))) {
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

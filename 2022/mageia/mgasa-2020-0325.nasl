# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0325");
  script_cve_id("CVE-2020-15586", "CVE-2020-16845");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0325");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0325.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27039");
  script_xref(name:"URL", value:"https://golang.org/doc/go1.13");
  script_xref(name:"URL", value:"https://golang.org/doc/devel/release.html#go1.13.minor");
  script_xref(name:"URL", value:"https://groups.google.com/forum/?utm_medium=email&utm_source=footer#!msg/golang-announce/XZNfaiwgt2w/E6gHDs32AQAJ");
  script_xref(name:"URL", value:"https://groups.google.com/forum/?utm_medium=email&utm_source=footer#!topic/golang-announce/NyPIaucMgXo");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-07/msg00082.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2020-0325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Servers where the Handler concurrently reads the request body and writes a
response can encounter a data race and crash. The httputil.ReverseProxy Handler
is affected (CVE-2020-15586).

Certain invalid inputs to ReadUvarint or ReadVarint could cause those functions
to read an unlimited number of bytes from the ByteReader argument before
returning an error. This could lead to processing more input than expected when
the caller is reading directly from the network and depends on ReadUvarint and
ReadVarint only consuming a small, bounded number of bytes, even from invalid
inputs (CVE-2020-16845).

The golang package has been updated to version 1.13.15, fixing these issues
and containing several other bug fixes and enhancements. See the 1.13 release
notes and other references for details.");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.13.15~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.13.15~1.mga7", rls:"MAGEIA7"))) {
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

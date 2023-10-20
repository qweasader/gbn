# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0462");
  script_cve_id("CVE-2018-17096", "CVE-2018-17097", "CVE-2018-17098");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0462");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0462.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23823");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-17096");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-17097");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-17098");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'soundtouch' package(s) announced via the MGASA-2018-0462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Assertion failure in BPMDetect class in BPMDetect.cpp (CVE-2018-17096).
Out-of-bounds heap write in WavOutFile::write() (CVE-2018-17097).
Heap corruption in WavFileBase class in WavFile.cpp (CVE-2018-17098).");

  script_tag(name:"affected", value:"'soundtouch' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64soundtouch-devel", rpm:"lib64soundtouch-devel~2.1.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soundtouch1", rpm:"lib64soundtouch1~2.1.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoundtouch-devel", rpm:"libsoundtouch-devel~2.1.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoundtouch1", rpm:"libsoundtouch1~2.1.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"soundtouch", rpm:"soundtouch~2.1.1~1.mga6", rls:"MAGEIA6"))) {
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

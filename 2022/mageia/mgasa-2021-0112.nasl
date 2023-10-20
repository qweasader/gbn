# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0112");
  script_cve_id("CVE-2020-25725", "CVE-2020-35376");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 16:05:00 +0000 (Tue, 23 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0112");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0112.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28474");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VLOYVJSM54IL6I5RY4QTJGRS7PIEG44X/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf' package(s) announced via the MGASA-2021-0112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Xpdf 4.02, SplashOutputDev::endType3Char(GfxState *state)
SplashOutputDev.cc:3079 is trying to use the freed `t3GlyphStack->cache`, which
causes an `heap-use-after-free` problem. The codes of a previous fix for nested
Type 3 characters wasn't correctly handling the case where a Type 3 char
referred to another char in the same Type 3 font (CVE-2020-25725).

Xpdf 4.02 allows stack consumption because of an incorrect subroutine reference
in a Type 1C font charstring, related to the FoFiType1C::getOp() function
(CVE-2020-35376).");

  script_tag(name:"affected", value:"'xpdf' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~4.03~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~4.03~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~4.03~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~4.03~1.mga8", rls:"MAGEIA8"))) {
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

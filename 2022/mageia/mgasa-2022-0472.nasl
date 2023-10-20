# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0472");
  script_cve_id("CVE-2022-38266");
  script_tag(name:"creation_date", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-15 03:40:00 +0000 (Thu, 15 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0472");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0472.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31266");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3233");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'leptonica, mingw-leptonica' package(s) announced via the MGASA-2022-0472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a denial of service vulnerability in leptonlib. It can
be made to crash with an arithmetic exception on specially crafted JPEG
files. (CVE-2022-38266)");

  script_tag(name:"affected", value:"'leptonica, mingw-leptonica' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"leptonica", rpm:"leptonica~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64leptonica-devel", rpm:"lib64leptonica-devel~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64leptonica5", rpm:"lib64leptonica5~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libleptonica-devel", rpm:"libleptonica-devel~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libleptonica5", rpm:"libleptonica5~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-leptonica", rpm:"mingw-leptonica~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-leptonica", rpm:"mingw32-leptonica~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-leptonica-static", rpm:"mingw32-leptonica-static~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-leptonica", rpm:"mingw64-leptonica~1.81.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-leptonica-static", rpm:"mingw64-leptonica-static~1.81.0~1.mga8", rls:"MAGEIA8"))) {
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

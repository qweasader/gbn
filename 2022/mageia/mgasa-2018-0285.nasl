# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0285");
  script_cve_id("CVE-2018-9018");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-12 03:15:00 +0000 (Sun, 12 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0285)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0285");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0285.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23156");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-05/msg00026.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4204");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3681-1/");
  script_xref(name:"URL", value:"https://legacy.imagemagick.org/script/changelog.php");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1133");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1156");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the MGASA-2018-0285 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Imagemagick has been updated to version 6.9.10.0 to fix several bugs and
possible security issues.

- Fixed numerous use of uninitialized values, integer overflow, memory
 exceeded, and timeouts
- Missing break when checking 'compliance' element.
- Fixed errant 'not enough pixel data'
- Fixed memory corruption for MVG paths
- A SVG rectangle with a width and height of 1, is a point
- Properly initialize SVG color style
- Heap buffer overflow fix");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_8", rpm:"lib64magick++-6Q16_8~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_6", rpm:"lib64magick-6Q16_6~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_8", rpm:"libmagick++-6Q16_8~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_6", rpm:"libmagick-6Q16_6~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.9.10.0~1.mga6", rls:"MAGEIA6"))) {
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

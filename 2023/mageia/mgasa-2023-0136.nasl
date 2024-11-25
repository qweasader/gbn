# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0136");
  script_cve_id("CVE-2023-1289");
  script_tag(name:"creation_date", value:"2023-04-12 04:12:44 +0000 (Wed, 12 Apr 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-30 15:07:29 +0000 (Thu, 30 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0136)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0136");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0136.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31761");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-j96m-mjp6-99xr");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-April/014341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the MGASA-2023-0136 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in ImageMagick where a specially created
SVG file loads itself and causes a segmentation fault. This flaw allows a
remote attacker to pass a specially crafted SVG file that leads to a
segmentation fault, generating many trash files in '/tmp,' resulting in a
denial of service. When ImageMagick crashes, it generates a lot of trash
files. These trash files can be large if the SVG file contains many render
actions. In a denial of service attack, if a remote attacker uploads an
SVG file of size t, ImageMagick generates files of size 103*t. If an
attacker uploads a 100M SVG, the server will generate about 10G.
(CVE-2023-1289)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.0.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.0.62~1.mga8.tainted", rls:"MAGEIA8"))) {
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

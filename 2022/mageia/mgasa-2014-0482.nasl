# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0482");
  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 12:52:58 +0000 (Mon, 17 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0482");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0482.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00036.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14526");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the MGASA-2014-0482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ImageMagick is vulnerable to a denial of service due to out-of-bounds memory
accesses in the resize code (CVE-2014-8354), PCX parser (CVE-2014-8355), DCM
decoder (CVE-2014-8562), and JPEG decoder (CVE-2014-8716).");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick7", rpm:"lib64magick7~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick7", rpm:"libmagick7~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.8.1.1~2.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_3", rpm:"lib64magick++-6Q16_3~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_1", rpm:"lib64magick-6Q16_1~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_3", rpm:"libmagick++-6Q16_3~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_1", rpm:"libmagick-6Q16_1~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.8.7.0~2.3.mga4", rls:"MAGEIA4"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0484");
  script_cve_id("CVE-2014-8355");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 18:18:54 +0000 (Mon, 17 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0484");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0484.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Nov/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14546");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the MGASA-2014-0484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick is vulnerable to an out of bounds read / heap Overflow in the
function ReadPCXImage in the file pcx.c. This can be exploited by a crafted
image file to cause a denial of service (CVE-2014-8355).");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.17~2.4.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.18~3.3.mga4", rls:"MAGEIA4"))) {
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

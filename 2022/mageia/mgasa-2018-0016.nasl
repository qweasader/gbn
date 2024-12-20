# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0016");
  script_cve_id("CVE-2017-2862", "CVE-2017-2870", "CVE-2017-6311", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 20:40:25 +0000 (Fri, 08 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0016");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0016.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21680");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-09/msg00031.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3418-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2.0' package(s) announced via the MGASA-2018-0016 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"JPEG gdk_pixbuf__jpeg_image_load_increment Code Execution Vulnerability
(CVE-2017-2862).

tiff_image_parse Code Execution Vulnerability (CVE-2017-2870).

Ariel Zelivansky discovered that the GDK-PixBuf library did not properly
handle printing certain error messages. If an user or automated system were
tricked into opening a specially crafted image file, a remote attacker
could use this flaw to cause GDK-PixBuf to crash, resulting in a denial of
service (CVE-2017-6311).

Out-of-bounds read on io-ico.c (CVE-2017-6312).

A dangerous integer underflow in io-icns.c (CVE-2017-6313).

Infinite loop in io-tiff.c (CVE-2017-6314).

Note, the CVE-2017-2862, CVE-2017-2870, and CVE-2017-6311 issues only
affected Mageia 5.");

  script_tag(name:"affected", value:"'gdk-pixbuf2.0' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.32.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.36.10~1.1.mga6", rls:"MAGEIA6"))) {
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

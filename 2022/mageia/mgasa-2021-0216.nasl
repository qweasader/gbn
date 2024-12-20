# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0216");
  script_cve_id("CVE-2021-29338");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-21 18:54:20 +0000 (Wed, 21 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0216)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0216");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0216.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2021-29338");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28851");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1950101");
  script_xref(name:"URL", value:"https://github.com/uclouvain/openjpeg/commit/b4700bc09d55ac17ff6bef9b0a867f6de527be17.patch");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-openjpeg2, openjpeg2' package(s) announced via the MGASA-2021-0216 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a flaw in the opj2_compress program in openjpeg2. An attacker who is able to submit a large number of image files to be processed in a directory by opj2_compress, could trigger a heap out-of-bounds write due to an integer overflow, which is caused by the large number of image files. The greatest threat posed by this flaw is to confidentiality, integrity, and availability.

This flaw affects the opj2_compress utility but is not in the openjpeg2 library. Therefore, the attack vector is local to the opj2_compress utility and would require an attacker to convince a user to open a directory with an extremely large number of files using opj2_compress, or a script to be feeding such arbitrary, untrusted files to opj2_compress (CVE-2021-29338).");

  script_tag(name:"affected", value:"'mingw-openjpeg2, openjpeg2' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openjp2_7", rpm:"lib64openjp2_7~2.4.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg2-devel", rpm:"lib64openjpeg2-devel~2.4.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2_7", rpm:"libopenjp2_7~2.4.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg2-devel", rpm:"libopenjpeg2-devel~2.4.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-openjpeg2", rpm:"mingw-openjpeg2~2.4.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openjpeg2", rpm:"mingw32-openjpeg2~2.4.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openjpeg2-tools", rpm:"mingw32-openjpeg2-tools~2.4.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openjpeg2", rpm:"mingw64-openjpeg2~2.4.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openjpeg2-tools", rpm:"mingw64-openjpeg2-tools~2.4.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.4.0~1.1.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64openjp2_7", rpm:"lib64openjp2_7~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg2-devel", rpm:"lib64openjpeg2-devel~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2_7", rpm:"libopenjp2_7~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg2-devel", rpm:"libopenjpeg2-devel~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-openjpeg2", rpm:"mingw-openjpeg2~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openjpeg2", rpm:"mingw32-openjpeg2~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-openjpeg2-tools", rpm:"mingw32-openjpeg2-tools~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openjpeg2", rpm:"mingw64-openjpeg2~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-openjpeg2-tools", rpm:"mingw64-openjpeg2-tools~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.4.0~1.1.mga8", rls:"MAGEIA8"))) {
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

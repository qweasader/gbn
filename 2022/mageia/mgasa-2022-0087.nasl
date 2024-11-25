# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0087");
  script_cve_id("CVE-2022-0561", "CVE-2022-0562");
  script_tag(name:"creation_date", value:"2022-03-07 04:10:01 +0000 (Mon, 07 Mar 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 21:29:15 +0000 (Thu, 17 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0087");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0087.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30108");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DZEHZ35XVO2VBZ4HHCMM6J6TQIDSBQOM/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2022-0087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Null source pointer passed as an argument to memcpy() function within
TIFFFetchStripThing() in tif_dirread.c in libtiff versions from 3.9.0 to
4.3.0 could lead to Denial of Service via crafted TIFF file.
(CVE-2022-0561)

Null source pointer passed as an argument to memcpy() function within
TIFFReadDirectory() in tif_dirread.c in libtiff versions from 4.0 to 4.3.0
could lead to Denial of Service via crafted TIFF file. (CVE-2022-0562)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.2.0~1.2.mga8", rls:"MAGEIA8"))) {
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

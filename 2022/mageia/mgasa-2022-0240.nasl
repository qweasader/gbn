# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0240");
  script_cve_id("CVE-2022-1354", "CVE-2022-1355", "CVE-2022-1622", "CVE-2022-1623");
  script_tag(name:"creation_date", value:"2022-06-27 04:43:55 +0000 (Mon, 27 Jun 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 14:57:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0240");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0240.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30571");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UXAFOP6QQRNZD3HPZ6BMCEZZOM4YIZMK/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2022-0240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-buffer-overflow in TIFFReadRawDataStriped() in tiffinfo.c.
(CVE-2022-1354)
Stack-buffer-overflow in tiffcp.c in main(). (CVE-2022-1355)
Out-of-bounds read in LZWDecode. (CVE-2022-1622, CVE-2022-1623)");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.2.0~1.5.mga8", rls:"MAGEIA8"))) {
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

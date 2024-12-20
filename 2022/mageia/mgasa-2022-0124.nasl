# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0124");
  script_cve_id("CVE-2018-25032");
  script_tag(name:"creation_date", value:"2022-04-01 04:08:56 +0000 (Fri, 01 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 18:50:40 +0000 (Wed, 30 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0124");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0124.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30204");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/03/24/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/03/25/2");
  script_xref(name:"URL", value:"https://www.zlib.net/ChangeLog.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib' package(s) announced via the MGASA-2022-0124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zlib before 1.2.12 allows memory corruption when deflating (i.e., when
compressing) if the input has many distant matches. (CVE-2018-25032)
Update to release 1.2.12 for additional bug fixes. See the changelog for
details.");

  script_tag(name:"affected", value:"'zlib' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip-devel", rpm:"lib64minizip-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip1", rpm:"lib64minizip1~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-devel", rpm:"lib64zlib-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-static-devel", rpm:"lib64zlib-static-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib1", rpm:"lib64zlib1~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip-devel", rpm:"libminizip-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-devel", rpm:"libzlib-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-static-devel", rpm:"libzlib-static-devel~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib1", rpm:"libzlib1~1.2.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib", rpm:"zlib~1.2.12~1.mga8", rls:"MAGEIA8"))) {
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

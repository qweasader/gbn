# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0186");
  script_cve_id("CVE-2017-9814");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 14:26:37 +0000 (Wed, 19 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2022-0186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0186");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0186.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30412");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5407-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cairo' package(s) announced via the MGASA-2022-0186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cairo-truetype-subset.c in cairo 1.15.6 and earlier allows remote attackers
to cause a denial of service (out-of-bounds read) because of mishandling of
an unexpected malloc(0) call. (CVE-2017-9814)");

  script_tag(name:"affected", value:"'cairo' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"cairo", rpm:"cairo~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cairo-devel", rpm:"lib64cairo-devel~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cairo-static-devel", rpm:"lib64cairo-static-devel~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cairo2", rpm:"lib64cairo2~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-devel", rpm:"libcairo-devel~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-static-devel", rpm:"libcairo-static-devel~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~6.2.mga8", rls:"MAGEIA8"))) {
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

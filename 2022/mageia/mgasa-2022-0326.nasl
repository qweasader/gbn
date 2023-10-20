# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0326");
  script_cve_id("CVE-2021-33657");
  script_tag(name:"creation_date", value:"2022-09-19 05:11:13 +0000 (Mon, 19 Sep 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 17:49:00 +0000 (Tue, 12 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0326)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0326");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0326.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30293");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010735.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RT4PK6MXMUBIFIGD2YA7HAH4DD43QU3Z/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5398-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sdl2' package(s) announced via the MGASA-2022-0326 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a heap overflow problem in video/SDL_pixels.c in SDL (Simple
DirectMedia Layer) 2.x to 2.0.18 versions. By crafting a malicious .BMP
file, an attacker can cause the application using this library to crash,
for denial of service, or for Code execution. (CVE-2021-33657)");

  script_tag(name:"affected", value:"'sdl2' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-devel", rpm:"lib64sdl2.0-devel~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0-static-devel", rpm:"lib64sdl2.0-static-devel~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sdl2.0_0", rpm:"lib64sdl2.0_0~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-devel", rpm:"libsdl2.0-devel~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0-static-devel", rpm:"libsdl2.0-static-devel~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsdl2.0_0", rpm:"libsdl2.0_0~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2", rpm:"sdl2~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sdl2-docs", rpm:"sdl2-docs~2.0.14~1.1.mga8", rls:"MAGEIA8"))) {
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

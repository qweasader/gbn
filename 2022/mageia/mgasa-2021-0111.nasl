# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0111");
  script_cve_id("CVE-2020-36241");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0111)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0111");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0111.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28454");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4733-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-autoar' package(s) announced via the MGASA-2021-0111 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yigit Can Yilmaz discovered that GNOME Autoar could extract files outside of
the intended directory. If a user were tricked into extracting a specially
crafted archive, a remote attacker could create files in arbitrary locations,
possibly leading to code execution (CVE-2020-36241).");

  script_tag(name:"affected", value:"'gnome-autoar' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-autoar", rpm:"gnome-autoar~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar-devel", rpm:"lib64gnome-autoar-devel~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar-gir0.1", rpm:"lib64gnome-autoar-gir0.1~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar0_0", rpm:"lib64gnome-autoar0_0~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar-devel", rpm:"libgnome-autoar-devel~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar-gir0.1", rpm:"libgnome-autoar-gir0.1~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar0_0", rpm:"libgnome-autoar0_0~0.2.3~2.1.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gnome-autoar", rpm:"gnome-autoar~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar-devel", rpm:"lib64gnome-autoar-devel~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar-gir0.1", rpm:"lib64gnome-autoar-gir0.1~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnome-autoar0_0", rpm:"lib64gnome-autoar0_0~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar-devel", rpm:"libgnome-autoar-devel~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar-gir0.1", rpm:"libgnome-autoar-gir0.1~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnome-autoar0_0", rpm:"libgnome-autoar0_0~0.2.4~2.1.mga8", rls:"MAGEIA8"))) {
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

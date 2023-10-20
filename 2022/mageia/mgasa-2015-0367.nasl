# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0367");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0367");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0367.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16739");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2739-1/");
  script_xref(name:"URL", value:"https://savannah.nongnu.org/bugs/?41309");
  script_xref(name:"URL", value:"https://savannah.nongnu.org/bugs/index.php?41590");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/11/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the MGASA-2015-0367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated freetype2 packages fix security vulnerabilities:

It was discovered that FreeType did not correctly handle certain malformed
font files. If a user were tricked into using a specially crafted font
file, a remote attacker could cause FreeType to crash or hang, resulting in
a denial of service, or possibly expose uninitialized memory
(Savannah bugs 41309 and 41590).");

  script_tag(name:"affected", value:"'freetype2' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.4.mga4.tainted", rls:"MAGEIA4"))) {
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

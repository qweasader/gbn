# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0373");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 17:28:19 +0000 (Fri, 03 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0373");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0373.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21834");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3442-1/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3995");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxfont, libxfont2' package(s) announced via the MGASA-2017-0373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the PatternMatch function in fontfile/fontdir.c in libXfont through
1.5.2 and 2.x before 2.0.2, an attacker with access to an X connection
can cause a buffer over-read during pattern matching of fonts, leading
to information disclosure or a crash (denial of service). This occurs
because '\0' characters are incorrectly skipped in situations involving
? characters. (CVE-2017-13720)

In the pcfGetProperties function in bitmap/pcfread.c in libXfont through
1.5.2 and 2.x before 2.0.2, a missing boundary check (for PCF files)
could be used by local attackers authenticated to an Xserver for a
buffer over-read, for information disclosure or a crash of the X server.
(CVE-2017-13722)");

  script_tag(name:"affected", value:"'libxfont, libxfont2' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont-devel", rpm:"lib64xfont-devel~1.5.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont1", rpm:"lib64xfont1~1.5.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont", rpm:"libxfont~1.5.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont-devel", rpm:"libxfont-devel~1.5.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont1", rpm:"libxfont1~1.5.1~1.1.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont-devel", rpm:"lib64xfont-devel~1.5.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont1", rpm:"lib64xfont1~1.5.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont2-devel", rpm:"lib64xfont2-devel~2.0.1~4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfont2_2", rpm:"lib64xfont2_2~2.0.1~4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont", rpm:"libxfont~1.5.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont-devel", rpm:"libxfont-devel~1.5.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont1", rpm:"libxfont1~1.5.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont2", rpm:"libxfont2~2.0.1~4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont2-devel", rpm:"libxfont2-devel~2.0.1~4.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfont2_2", rpm:"libxfont2_2~2.0.1~4.1.mga6", rls:"MAGEIA6"))) {
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

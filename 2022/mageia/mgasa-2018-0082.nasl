# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0082");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-08 14:34:18 +0000 (Mon, 08 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0082");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0082.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22368");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2018-0001.html");
  script_xref(name:"URL", value:"https://www.webkitgtk.org/2018/01/10/webkitgtk2.18.5-released.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2018-0082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The webkit2 package has been updated to version 2.18.5, containing
Spectre mitigations.");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2-devel", rpm:"lib64webkit2-devel~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2-devel", rpm:"libwebkit2-devel~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.18.5~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-jsc", rpm:"webkit2-jsc~2.18.5~1.mga6", rls:"MAGEIA6"))) {
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

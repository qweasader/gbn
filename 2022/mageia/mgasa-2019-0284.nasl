# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0284");
  script_cve_id("CVE-2019-14822");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-04 15:58:11 +0000 (Wed, 04 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0284)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0284");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0284.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25434");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/09/13/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ibus' package(s) announced via the MGASA-2019-0284 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that any unprivileged user could monitor and send method
calls to the ibus bus of another user, due to a misconfiguration during the
setup of the DBus server. When ibus is in use, a local attacker, who discovers
the UNIX socket used by another user connected on a graphical environment,
could use this flaw to intercept all keystrokes of the victim user or modify
input related configurations through DBus method calls (CVE-2019-14822).");

  script_tag(name:"affected", value:"'ibus' package(s) on Mageia 6, Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"ibus", rpm:"ibus~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-devel", rpm:"ibus-devel~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk", rpm:"ibus-gtk~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3", rpm:"ibus-gtk3~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-ui-gtk3", rpm:"ibus-ui-gtk3~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ibus-gir1.0", rpm:"lib64ibus-gir1.0~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ibus1.0_5", rpm:"lib64ibus1.0_5~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-gir1.0", rpm:"libibus-gir1.0~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus1.0_5", rpm:"libibus1.0_5~1.5.16~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ibus", rpm:"ibus~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-devel", rpm:"ibus-devel~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk", rpm:"ibus-gtk~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-gtk3", rpm:"ibus-gtk3~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibus-ui-gtk3", rpm:"ibus-ui-gtk3~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ibus-gir1.0", rpm:"lib64ibus-gir1.0~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ibus1.0_5", rpm:"lib64ibus1.0_5~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus-gir1.0", rpm:"libibus-gir1.0~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibus1.0_5", rpm:"libibus1.0_5~1.5.20~1.1.mga7", rls:"MAGEIA7"))) {
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

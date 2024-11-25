# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0021");
  script_cve_id("CVE-2013-6891");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0021");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0021.html");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L4319");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2082-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12257");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the MGASA-2014-0021 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cups packages fix security vulnerability:

Jann Horn discovered that the CUPS lppasswd tool incorrectly read a user
configuration file in certain configurations. A local attacker could use
this to read sensitive information from certain files, bypassing access
restrictions (CVE-2013-6891).");

  script_tag(name:"affected", value:"'cups' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cups", rpm:"php-cups~1.5.4~9.1.mga3", rls:"MAGEIA3"))) {
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

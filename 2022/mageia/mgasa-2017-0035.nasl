# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0035");
  script_cve_id("CVE-2016-10164");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-22 16:19:18 +0000 (Wed, 22 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0035");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0035.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/01/25/7");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20180");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxpm' package(s) announced via the MGASA-2017-0035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of boundary write has been found in libXpm before 3.5.12 which
can be exploited by an attacker through maliciously crafted XPM files.
To trigger the vulnerability, a program must explicitly request to also
parse XPM extensions while reading files. The motif toolkit and xdm are
two among some programs that set the flag (XpmReturnExtensions). It can
only be exploited on 64-bit systems (CVE-2016-10164).");

  script_tag(name:"affected", value:"'libxpm' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm-devel", rpm:"lib64xpm-devel~3.5.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xpm4", rpm:"lib64xpm4~3.5.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm", rpm:"libxpm~3.5.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm-devel", rpm:"libxpm-devel~3.5.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxpm4", rpm:"libxpm4~3.5.12~1.mga5", rls:"MAGEIA5"))) {
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

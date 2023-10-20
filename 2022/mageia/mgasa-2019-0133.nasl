# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0133");
  script_cve_id("CVE-2018-3846", "CVE-2018-3848", "CVE-2018-3849");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-03 16:17:00 +0000 (Wed, 03 Feb 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0133.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24586");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1563915");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568184");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568189");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cfitsio' package(s) announced via the MGASA-2019-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-3846: Unsafe use of sprintf() can allow a remote unauthenticated
attacker to execute arbitrary code
CVE-2018-3848: Stack-based buffer overflow in ffghbn() allows for
potential code execution
CVE-2018-3849: Stack-based buffer overflow in ffghtb() allows for
potential code execution");

  script_tag(name:"affected", value:"'cfitsio' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cfitsio", rpm:"cfitsio~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cfitsio-devel", rpm:"lib64cfitsio-devel~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cfitsio-static-devel", rpm:"lib64cfitsio-static-devel~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cfitsio5", rpm:"lib64cfitsio5~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcfitsio-devel", rpm:"libcfitsio-devel~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcfitsio-static-devel", rpm:"libcfitsio-static-devel~3.430~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcfitsio5", rpm:"libcfitsio5~3.430~1.1.mga6", rls:"MAGEIA6"))) {
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

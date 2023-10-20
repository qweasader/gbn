# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131121");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2015-11-08 11:02:15 +0000 (Sun, 08 Nov 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0420");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0420.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16924");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1615/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2772-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql9.3, postgresql9.4' package(s) announced via the MGASA-2015-0420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Josh Kupershmidt discovered the pgCrypto extension could expose
several bytes of server memory if the crypt() function was provided a
too-short salt. An attacker could use this flaw to read private data.
(CVE-2015-5288)

Oskari Saarenmaa discovered that the json and jsonb handlers could exhaust
available stack space. An attacker could use this flaw to perform a denial
of service attack. (CVE-2015-5289)

The postgresql9.3 and postgresql9.4 packages have been updated to versions
9.3.10 and 9.4.5, respectively, to fix these issues.
See the upstream release notes for more details.");

  script_tag(name:"affected", value:"'postgresql9.3, postgresql9.4' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.3_6", rpm:"lib64ecpg9.3_6~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ecpg9.4_6", rpm:"lib64ecpg9.4_6~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pq9.3_5.6", rpm:"lib64pq9.3_5.6~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.3_6", rpm:"libecpg9.3_6~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg9.4_6", rpm:"libecpg9.4_6~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq9.3_5.6", rpm:"libpq9.3_5.6~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3", rpm:"postgresql9.3~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-contrib", rpm:"postgresql9.3-contrib~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-devel", rpm:"postgresql9.3-devel~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-docs", rpm:"postgresql9.3-docs~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pl", rpm:"postgresql9.3-pl~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plperl", rpm:"postgresql9.3-plperl~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpgsql", rpm:"postgresql9.3-plpgsql~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-plpython", rpm:"postgresql9.3-plpython~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-pltcl", rpm:"postgresql9.3-pltcl~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.3-server", rpm:"postgresql9.3-server~9.3.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4", rpm:"postgresql9.4~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-contrib", rpm:"postgresql9.4-contrib~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-devel", rpm:"postgresql9.4-devel~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-docs", rpm:"postgresql9.4-docs~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pl", rpm:"postgresql9.4-pl~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plperl", rpm:"postgresql9.4-plperl~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpgsql", rpm:"postgresql9.4-plpgsql~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-plpython", rpm:"postgresql9.4-plpython~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-pltcl", rpm:"postgresql9.4-pltcl~9.4.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql9.4-server", rpm:"postgresql9.4-server~9.4.5~1.mga5", rls:"MAGEIA5"))) {
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

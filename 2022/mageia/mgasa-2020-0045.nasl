# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0045");
  script_cve_id("CVE-2019-8354", "CVE-2019-8355", "CVE-2019-8356", "CVE-2019-8357");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-28 10:29:00 +0000 (Tue, 28 May 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0045");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0045.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25289");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sox/bugs/319/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sox/bugs/320/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/sox/bugs/321/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sox' package(s) announced via the MGASA-2020-0045 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sox packages fix security vulnerabilities:

It was discovered that SoX incorrectly handled certain MP3 files. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2019-8354, CVE-2019-8355, CVE-2019-8356, CVE-2019-8357)");

  script_tag(name:"affected", value:"'sox' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sox-devel", rpm:"lib64sox-devel~14.4.3~0.git20200117.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sox3", rpm:"lib64sox3~14.4.3~0.git20200117.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox-devel", rpm:"libsox-devel~14.4.3~0.git20200117.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox3", rpm:"libsox3~14.4.3~0.git20200117.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.3~0.git20200117.1.mga7", rls:"MAGEIA7"))) {
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

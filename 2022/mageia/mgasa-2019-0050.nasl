# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0050");
  script_cve_id("CVE-2018-20544", "CVE-2018-20545", "CVE-2018-20546", "CVE-2018-20547", "CVE-2018-20548", "CVE-2018-20549");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-11 13:26:00 +0000 (Fri, 11 Jan 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0050");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0050.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24208");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3860-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca' package(s) announced via the MGASA-2019-0050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libcaca incorrectly handled certain images. An
attacker could possibly use this issue to cause a denial of service
(CVE-2018-20544).

It was discovered that libcaca incorrectly handled certain images. An
attacker could possibly use this issue to execute arbitrary code
(CVE-2018-20545, CVE-2018-20548, CVE-2018-20459).

It was discovered that libcaca incorrectly handled certain images. An
attacker could possibly use this issue to access sensitive information
(CVE-2018-20546, CVE-2018-20547).");

  script_tag(name:"affected", value:"'libcaca' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca-devel", rpm:"lib64caca-devel~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca0", rpm:"lib64caca0~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca", rpm:"libcaca~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-caca", rpm:"python-caca~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca", rpm:"ruby-caca~0.99~0.beta18.13.1.mga6", rls:"MAGEIA6"))) {
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

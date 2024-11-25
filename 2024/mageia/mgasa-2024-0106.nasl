# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0106");
  script_cve_id("CVE-2024-1013");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-04-05T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0106");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0106.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33031");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6715-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unixODBC' package(s) announced via the MGASA-2024-0106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that unixODBC incorrectly handled certain bytes.
An attacker could use this issue to execute arbitrary code or cause
a crash.");

  script_tag(name:"affected", value:"'unixODBC' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64unixODBC-devel", rpm:"lib64unixODBC-devel~2.3.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64unixODBC2", rpm:"lib64unixODBC2~2.3.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunixODBC-devel", rpm:"libunixODBC-devel~2.3.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunixODBC2", rpm:"libunixODBC2~2.3.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unixODBC", rpm:"unixODBC~2.3.11~1.1.mga9", rls:"MAGEIA9"))) {
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

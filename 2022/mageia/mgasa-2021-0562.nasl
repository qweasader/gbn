# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0562");
  script_cve_id("CVE-2021-32765");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 15:43:09 +0000 (Thu, 07 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0562)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0562");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0562.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29549");
  script_xref(name:"URL", value:"https://github.com/redis/hiredis/security/advisories/GHSA-hfm9-39pp-55p2");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2783");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hiredis' package(s) announced via the MGASA-2021-0562 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated hiredis packages fix security vulnerability:

It was discovered that there was an integer-overflow vulnerability in
hiredis, a C client library for communicating with Redis databases.
This occurred within the handling and parsing of 'multi-bulk' replies
(CVE-2021-32765).");

  script_tag(name:"affected", value:"'hiredis' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"hiredis", rpm:"hiredis~0.13.3~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hiredis-devel", rpm:"lib64hiredis-devel~0.13.3~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hiredis0.13", rpm:"lib64hiredis0.13~0.13.3~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhiredis-devel", rpm:"libhiredis-devel~0.13.3~6.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhiredis0.13", rpm:"libhiredis0.13~0.13.3~6.1.mga8", rls:"MAGEIA8"))) {
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

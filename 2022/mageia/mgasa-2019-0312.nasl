# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0312");
  script_cve_id("CVE-2019-17266");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 15:17:07 +0000 (Thu, 10 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0312)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0312");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0312.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25642");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4152-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the MGASA-2019-0312 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libsoup package fixes security vulnerability:

It was discovered that libsoup incorrectly handled parsing certain NTLM
messages. If a user or automated system were tricked into connecting to
a malicious server, a remote attacker could possibly use this issue to
cause a denial of service (CVE-2019-17266).");

  script_tag(name:"affected", value:"'libsoup' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-devel", rpm:"lib64soup-devel~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-gir2.4", rpm:"lib64soup-gir2.4~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup2.4_1", rpm:"lib64soup2.4_1~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-gir2.4", rpm:"libsoup-gir2.4~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-i18n", rpm:"libsoup-i18n~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2.4_1", rpm:"libsoup2.4_1~2.66.1~2.1.mga7", rls:"MAGEIA7"))) {
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

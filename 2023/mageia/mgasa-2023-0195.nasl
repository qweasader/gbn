# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0195");
  script_cve_id("CVE-2023-2650");
  script_tag(name:"creation_date", value:"2023-06-09 04:12:22 +0000 (Fri, 09 Jun 2023)");
  script_version("2023-08-31T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-29 18:04:00 +0000 (Tue, 29 Aug 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0195.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31981");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230530.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2023-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Possible DoS translating ASN.1 object identifiers. (CVE-2023-2650)");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.1", rpm:"lib64openssl1.1~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.1", rpm:"libopenssl1.1~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.1.1u~1.mga8", rls:"MAGEIA8"))) {
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
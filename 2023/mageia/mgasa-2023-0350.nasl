# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0350");
  script_cve_id("CVE-2023-37464");
  script_tag(name:"creation_date", value:"2023-12-19 04:12:31 +0000 (Tue, 19 Dec 2023)");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:15:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0350");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0350.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32274");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DFWAPMYYVBO2U65HPYDTBEKNSXG4TP5C/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cjose' package(s) announced via the MGASA-2023-0350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
The AES GCM decryption routine incorrectly uses the Tag length from the
actual Authentication Tag provided in the JWE. The spec says that a
fixed length of 16 octets must be applied. Therefore this bug allows an
attacker to provide a truncated Authentication Tag and to modify the JWE
accordingly. (CVE-2023-37464)");

  script_tag(name:"affected", value:"'cjose' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"cjose", rpm:"cjose~0.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cjose-devel", rpm:"lib64cjose-devel~0.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cjose0", rpm:"lib64cjose0~0.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjose-devel", rpm:"libcjose-devel~0.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjose0", rpm:"libcjose0~0.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"cjose", rpm:"cjose~0.6.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cjose-devel", rpm:"lib64cjose-devel~0.6.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cjose0", rpm:"lib64cjose0~0.6.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjose-devel", rpm:"libcjose-devel~0.6.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcjose0", rpm:"libcjose0~0.6.1~3.1.mga9", rls:"MAGEIA9"))) {
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

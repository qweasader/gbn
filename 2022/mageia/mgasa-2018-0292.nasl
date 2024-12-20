# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0292");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 19:33:08 +0000 (Wed, 01 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0292");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0292.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/06/13/10");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23162");
  script_xref(name:"URL", value:"https://lists.gnupg.org/pipermail/gnupg-announce/2018q2/000425.html");
  script_xref(name:"URL", value:"https://neopg.io/blog/gpg-signature-spoof/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3675-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg, gnupg2, python-gnupg' package(s) announced via the MGASA-2018-0292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gnupg, gnupg2, and python-gnupg packages fix security vulnerability:

Marcus Brinkmann discovered that during decryption or verification, GnuPG did
not properly filter out terminal sequences when reporting the original
filename. An attacker could use this to specially craft a file that would
cause an application parsing GnuPG output to incorrectly interpret the status
of the cryptographic operation reported by GnuPG (CVE-2018-12020).");

  script_tag(name:"affected", value:"'gnupg, gnupg2, python-gnupg' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.19~1.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.27~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gnupg", rpm:"python-gnupg~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gnupg", rpm:"python3-gnupg~0.3.6~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.23~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.1.21~3.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gnupg", rpm:"python-gnupg~0.3.8~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gnupg", rpm:"python3-gnupg~0.3.8~2.1.mga6", rls:"MAGEIA6"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0247");
  script_cve_id("CVE-2021-33582");
  script_tag(name:"creation_date", value:"2022-07-06 04:44:30 +0000 (Wed, 06 Jul 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 11:12:33 +0000 (Thu, 09 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0247)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0247");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0247.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30079");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/WJZB45QBUN7CZFGOWCZYUYACNBTX7LVS/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3052");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd' package(s) announced via the MGASA-2022-0247 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cyrus IMAP before 3.4.2 allows remote attackers to cause a denial of
service (multiple-minute daemon hang) via input that is mishandled during
hash-table interaction. Because there are many insertions into a single
bucket, strcmp becomes slow. (CVE-2021-33582)");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd-devel", rpm:"lib64cyrus-imapd-devel~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd0", rpm:"lib64cyrus-imapd0~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd-devel", rpm:"libcyrus-imapd-devel~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd0", rpm:"libcyrus-imapd0~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.5.15~3.1.mga8", rls:"MAGEIA8"))) {
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

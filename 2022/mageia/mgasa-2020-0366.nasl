# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0366");
  script_cve_id("CVE-2020-15953");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:03:51 +0000 (Thu, 30 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0366");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0366.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27168");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QFBWNA5REI5ZGW2DAOEAVHM23MOU6O5J/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2329");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libetpan' package(s) announced via the MGASA-2020-0366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibEtPan through 1.9.4, as used in MailCore 2 through 0.6.3 and other
products, has a STARTTLS buffering issue that affects IMAP, SMTP, and POP3.
When a server sends a 'begin TLS' response, the client reads additional data
(e.g., from a meddler-in-the-middle attacker) and evaluates it in a TLS
context, aka 'response injection'. (CVE-2020-15953).");

  script_tag(name:"affected", value:"'libetpan' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64etpan-devel", rpm:"lib64etpan-devel~1.9.3~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64etpan20", rpm:"lib64etpan20~1.9.3~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan", rpm:"libetpan~1.9.3~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan-devel", rpm:"libetpan-devel~1.9.3~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan20", rpm:"libetpan20~1.9.3~1.1.mga7", rls:"MAGEIA7"))) {
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

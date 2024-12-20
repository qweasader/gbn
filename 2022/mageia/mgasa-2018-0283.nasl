# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0283");
  script_cve_id("CVE-2017-10788", "CVE-2017-10789");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 18:24:31 +0000 (Wed, 12 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0283");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0283.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23154");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-05/msg00138.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBD-mysql' package(s) announced via the MGASA-2018-0283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated perl-DBD-mysql package fixes security vulnerabilities:

The DBD::mysql Perl module through 4.043 for Perl allows remote attackers to
cause a denial of service (use-after-free and application crash) or possibly
have unspecified other impact by triggering certain error responses from a
MySQL server or a loss of a network connection to a MySQL server. The
use-after-free defect was introduced by relying on incorrect Oracle
mysql_stmt_close documentation and code examples (CVE-2017-10788).

The DBD::mysql Perl module, when used with mysql_ssl=1 setting enabled, means
that SSL is optional (even though this setting's documentation has a 'your communication with the server will be encrypted' statement), which could lead
man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack
(CVE-2017-10789).");

  script_tag(name:"affected", value:"'perl-DBD-mysql' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.46.0~1.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-mysql", rpm:"perl-DBD-mysql~4.46.0~1.mga6", rls:"MAGEIA6"))) {
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

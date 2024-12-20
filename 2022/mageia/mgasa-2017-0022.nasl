# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0022");
  script_cve_id("CVE-2016-10033", "CVE-2017-5223");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 16:30:42 +0000 (Thu, 30 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2017-0022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0022");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0022.html");
  script_xref(name:"URL", value:"http://kalilinux.co/2017/01/12/phpmailer-cve-2017-5223-local-information-disclosure-vulnerability-analysis/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20069");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JTXZSKTKOWTVEXDS76R6GJGI3MLA2LL5/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3750");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phpmailer' package(s) announced via the MGASA-2017-0022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHPMailer, a popular library to send email from
PHP applications, allowed a remote attacker to execute code if they were
able to provide a crafted Sender address (CVE-2016-10033).

It was discovered that PHPMailer prior to 5.2.22 contained a local file
disclosure vulnerability if content passed to `msgHTML()` was sourced
from unfiltered user input (CVE-2017-5223).");

  script_tag(name:"affected", value:"'php-phpmailer' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-phpmailer", rpm:"php-phpmailer~5.2.22~1.mga5", rls:"MAGEIA5"))) {
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

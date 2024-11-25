# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0108");
  script_cve_id("CVE-2018-1000858");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-13 16:43:02 +0000 (Wed, 13 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0108");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0108.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24178");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00009.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3853-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2' package(s) announced via the MGASA-2019-0108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GnuPG version 2.1.12 - 2.2.11 contains a Cross ite Request Forgery (CSRF)
vulnerability in dirmngr that can result in Attacker controlled CSRF,
Information Disclosure, DoS. This attack appear to be exploitable via
Victim must perform a WKD request, e.g. enter an email address in the
composer window of Thunderbird/Enigmail. This vulnerability appears to
have been fixed in after commit 4a4bb874f63741026bd26264c43bb32b1099f060.
(CVE-2018-1000858)");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.1.21~3.2.mga6", rls:"MAGEIA6"))) {
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

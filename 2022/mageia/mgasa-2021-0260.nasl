# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0260");
  script_cve_id("CVE-2021-23980");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 15:19:38 +0000 (Mon, 27 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2021-0260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0260");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0260.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28986");
  script_xref(name:"URL", value:"https://github.com/mozilla/bleach/security/advisories/GHSA-vv2x-vrpj-qqpq");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YFAKMJGUZHUTZ53ZAID6PRVP5MSLXPGV/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4892.en.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-bleach' package(s) announced via the MGASA-2021-0260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that python-bleach, a whitelist-based HTML-sanitizing
library, is prone to a mutation XSS vulnerability in bleach.clean when 'svg'
or 'math' are in the allowed tags, 'p' or 'br' are in allowed tags, 'style',
'title', 'noscript', 'script', 'textarea', 'noframes', 'iframe', or 'xmp' are
in allowed tags and 'strip_comments=False' is set (CVE-2021-23980).");

  script_tag(name:"affected", value:"'python-bleach' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-bleach", rpm:"python-bleach~3.1.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-bleach", rpm:"python2-bleach~3.1.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bleach", rpm:"python3-bleach~3.1.4~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-bleach", rpm:"python-bleach~3.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bleach", rpm:"python3-bleach~3.3.0~1.mga8", rls:"MAGEIA8"))) {
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

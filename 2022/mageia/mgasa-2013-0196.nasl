# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0196");
  script_cve_id("CVE-2013-3551", "CVE-2013-4088");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 19:33:18 +0000 (Wed, 26 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2013-0196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0196");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0196.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2696");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2712");
  script_xref(name:"URL", value:"http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2013-03/");
  script_xref(name:"URL", value:"http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2013-04/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10352");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs' package(s) announced via the MGASA-2013-0196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An attacker with a valid agent login could manipulate URLs in the ticket
watch mechanism to see contents of tickets they are not permitted to see
(CVE-2013-3551, CVE-2013-4088).");

  script_tag(name:"affected", value:"'otrs' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.8~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~3.2.8~1.mga3", rls:"MAGEIA3"))) {
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

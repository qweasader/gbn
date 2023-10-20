# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0146");
  script_cve_id("CVE-2021-28117");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-01 14:58:00 +0000 (Thu, 01 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0146)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0146");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0146.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28581");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20210310-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'discover' package(s) announced via the MGASA-2021-0146 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Discover fetches the description and related texts of some applications/plugins
from store.kde.org. That text is displayed to the user, after turning into a
clickable link any part of the text that looks like a link. This is done for
any kind of link, be it smb:// nfs:// etc. when in fact it only makes sense for
http/https links. Opening links that the user has clicked on is not very
problematic but can be used to chain to other attack vectors. Given the
intended functionality of the feature is just for http/https links it makes
sense to do that verification (CVE-2021-28117).");

  script_tag(name:"affected", value:"'discover' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"discover", rpm:"discover~5.15.4~2.2.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"discover", rpm:"discover~5.20.4~3.1.mga8", rls:"MAGEIA8"))) {
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

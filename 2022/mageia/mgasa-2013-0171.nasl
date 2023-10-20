# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0171");
  script_cve_id("CVE-2013-2149", "CVE-2013-2150");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0171)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0171");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0171.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10452");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-028/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud' package(s) announced via the MGASA-2013-0171 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerabilities in js/viewer.js inside the
files_videoviewer application via multiple unspecified vectors in all
ownCloud versions prior to 5.0.7 and 4.5.12 allows authenticated remote
attackers to inject arbitrary web script or HTML via shared files
(CVE-2013-2150).

Cross-site scripting (XSS) vulnerabilities in core/js/oc-dialogs.js via
multiple unspecified vectors in all ownCloud versions prior to 5.0.7
and other versions before 4.0.16 allows authenticated remote attackers
to inject arbitrary web script or HTML via shared files (CVE-2013-2149).");

  script_tag(name:"affected", value:"'owncloud' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~5.0.7~1.mga3", rls:"MAGEIA3"))) {
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

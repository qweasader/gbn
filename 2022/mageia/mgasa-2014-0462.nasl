# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0462");
  script_cve_id("CVE-2014-3994", "CVE-2014-3995");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0462");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0462.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13504");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134416.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-djblets' package(s) announced via the MGASA-2014-0462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in util/templatetags/djblets_js.py
in Djblets before 0.7.30 for Django, as used in Review Board, allows remote
attackers to inject arbitrary web script or HTML via a JSON object, as
demonstrated by the name field when changing a user name (CVE-2014-3994).

Cross-site scripting (XSS) vulnerability in
gravatars/templatetags/gravatars.py in Djblets before 0.7.30 Django allows
remote attackers to inject arbitrary web script or HTML via a user display
name (CVE-2014-3995).");

  script_tag(name:"affected", value:"'python-djblets' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-django14-pipeline", rpm:"python-django14-pipeline~0.7.30~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-djblets", rpm:"python-djblets~0.7.30~1.1.mga4", rls:"MAGEIA4"))) {
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

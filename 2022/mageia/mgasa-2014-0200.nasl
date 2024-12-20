# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0200");
  script_cve_id("CVE-2014-1517");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0200");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0200.html");
  script_xref(name:"URL", value:"http://www.bugzilla.org/releases/4.4.4/release-notes.html");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/4.0.11/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10897");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-April/132309.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bugzilla' package(s) announced via the MGASA-2014-0200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated bugzilla packages fix security vulnerability:

The login form in Bugzilla 2.x, 3.x, 4.x before 4.4.3, and 4.5.x before
4.5.3 does not properly handle a correctly authenticated but unintended
login attempt, which makes it easier for remote authenticated users to
obtain sensitive information by arranging for a victim to login to the
attacker's account and then submit a vulnerability report, related to a
'login CSRF' issue (CVE-2014-1517).");

  script_tag(name:"affected", value:"'bugzilla' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"bugzilla", rpm:"bugzilla~4.4.4~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bugzilla-contrib", rpm:"bugzilla-contrib~4.4.4~1.1.mga4", rls:"MAGEIA4"))) {
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

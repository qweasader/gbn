# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0379");
  script_cve_id("CVE-2014-3617");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0379");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0379.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14081");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.6.5_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=269089");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=269590");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=269591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2014-0379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated moodle packages fix security vulnerabilities:

In Moodle before 2.6.5, users who had not yet posted the required answer in
a Q&A forum in order to access past posts were able to see the name of the
last person who had posted, as other authors are visible in
/mod/forum/view.php before the student has posted their own answer
(CVE-2014-3617).");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.5~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.5~1.mga4", rls:"MAGEIA4"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61477");
  script_cve_id("CVE-2008-2711");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2008-210-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|11\.0|12\.0|12\.1|8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2008-210-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.495740");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fetchmail' package(s) announced via the SSA:2008-210-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New fetchmail packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, 11.0, 12.0, 12.1, and -current to fix security issues.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 12.1 ChangeLog:
+--------------------------+
patches/packages/fetchmail-6.3.8-i486-3_slack12.1.tgz:
 Patched to fix a possible denial of service when '-v -v' options are used.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'fetchmail' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware 11.0, Slackware 12.0, Slackware 12.1, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-1_slack10.0", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-1_slack10.1", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-3_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-3_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i386-1_slack8.1", rls:"SLK8.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i386-1_slack9.0", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-1_slack9.1", rls:"SLK9.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"fetchmail", ver:"6.3.8-i486-3", rls:"SLKcurrent"))) {
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

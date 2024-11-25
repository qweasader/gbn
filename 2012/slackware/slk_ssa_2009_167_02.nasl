# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64259");
  script_cve_id("CVE-2009-0023", "CVE-2009-1955");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2009-167-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(11\.0|12\.0|12\.1|12\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-167-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.538210");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr-util' package(s) announced via the SSA:2009-167-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New apr-util (and apr) packages are available for Slackware 11.0, 12.0, 12.1,
12.2, and -current to fix security issues. The issues are with apr-util, but
older Slackware releases will require a new version of the apr package as well.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]
 [link moved to references]


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/apr-1.3.5-i486-1_slack12.2.tgz: Upgraded.
patches/packages/apr-util-1.3.7-i486-1_slack12.2.tgz: Upgraded.
 Fix underflow in apr_strmatch_precompile.
 Fix a denial of service attack against the apr_xml_* interface
 using the 'billion laughs' entity expansion technique.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'apr-util' package(s) on Slackware 11.0, Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware current.");

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

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack11.0", rls:"SLK11.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1_slack12.2", rls:"SLK12.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr", ver:"1.3.5-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.3.7-x86_64-1", rls:"SLKcurrent"))) {
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

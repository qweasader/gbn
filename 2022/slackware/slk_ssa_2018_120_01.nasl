# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2018.120.01");
  script_cve_id("CVE-2004-0941", "CVE-2006-3376", "CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3477", "CVE-2009-3546", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-9011", "CVE-2016-9317", "CVE-2017-6362");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 18:31:20 +0000 (Thu, 16 Mar 2017)");

  script_name("Slackware: Security Advisory (SSA:2018-120-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|13\.1|13\.37|14\.0|14\.1|14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2018-120-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.620340");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwmf' package(s) announced via the SSA:2018-120-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libwmf packages are available for Slackware 13.0, 13.1, 13.37, 14.0, 14.1,
14.2, and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/libwmf-0.2.8.4-i586-7_slack14.1.txz: Rebuilt.
 Patched denial of service and possible execution of arbitrary code
 security issues.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libwmf' package(s) on Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

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

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i486-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i486-6_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-6_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i486-6_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-6_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i486-6_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-6_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i486-6_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-6_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i586-7_slack14.1", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-7_slack14.1", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-i586-8", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libwmf", ver:"0.2.8.4-x86_64-8", rls:"SLKcurrent"))) {
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

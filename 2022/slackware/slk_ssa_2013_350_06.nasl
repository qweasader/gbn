# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2013.350.06");
  script_cve_id("CVE-2013-4164");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2013-350-06)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.1|13\.37|14\.0|14\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2013-350-06");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.484609");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2013/11/22/heap-overflow-in-floating-point-parsing-cve-2013-4164/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the SSA:2013-350-06 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New ruby packages are available for Slackware 13.1, 13.37, 14.0, 14.1,
and -current to fix a security issue.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/ruby-1.9.3_p484-i486-1_slack14.1.txz: Upgraded.
 This update fixes a heap overflow in floating point parsing. A specially
 crafted string could cause a heap overflow leading to a denial of service
 attack via segmentation faults and possibly arbitrary code execution.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'ruby' package(s) on Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware current.");

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

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-x86_64-1_slack13.1", rls:"SLK13.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-x86_64-1_slack13.37", rls:"SLK13.37"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-i486-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-x86_64-1_slack14.0", rls:"SLK14.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-x86_64-1_slack14.1", rls:"SLK14.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"1.9.3_p484-x86_64-1", rls:"SLKcurrent"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58308");
  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2007-152-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2007-152-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.571857");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#seamonkey");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#thunderbird");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-seamonkey-thunderbird' package(s) announced via the SSA:2007-152-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox and seamonkey packages are available for Slackware 10.2,
11.0, and -current to fix security issues. New thunderbird packages are
available for Slackware 10.2 and 11.0 to fix security issues.

More details about this issue may be found at these links:
 [link moved to references]
 [link moved to references]
 [link moved to references]


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-1.5.0.12-i686-1.tgz:
 Upgraded to firefox-1.5.0.12.
 This upgrade fixes several possible security bugs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/mozilla-thunderbird-1.5.0.12-i686-1.tgz:
 Upgraded to thunderbird-1.5.0.12.
 This upgrade fixes several possible security bugs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/seamonkey-1.1.2-i486-1_slack11.0.tgz:
 Upgraded to seamonkey-1.1.2.
 This upgrade fixes several possible security bugs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
extra/mozilla-firefox-2.0.0.4/mozilla-firefox-2.0.0.4-i686-1.tgz:
 Upgraded to firefox-2.0.0.4.
 This upgrade fixes several possible security bugs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'firefox-seamonkey-thunderbird' package(s) on Slackware 10.2, Slackware 11.0, Slackware current.");

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

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.5.0.12-i686-1", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.12-i686-1", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.5.0.12-i686-1", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.4-i686-1", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.12-i686-1", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"1.1.2-i486-1_slack11.0", rls:"SLK11.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.4-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"1.1.2-i486-1", rls:"SLKcurrent"))) {
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

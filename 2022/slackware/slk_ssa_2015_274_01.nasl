# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2015.274.01");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2015-274-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2015-274-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2015&m=slackware-security.360174");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird' package(s) announced via the SSA:2015-274-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-thunderbird packages are available for Slackware 14.1 and -current
to fix security issues.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/mozilla-thunderbird-38.3.0-i486-1_slack14.1.txz: Upgraded.
 This release contains security fixes and improvements.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Slackware 14.1, Slackware current.");

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

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"38.3.0-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"38.3.0-x86_64-1_slack14.1", rls:"SLK14.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"38.3.0-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"38.3.0-x86_64-1", rls:"SLKcurrent"))) {
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

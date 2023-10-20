# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53945");
  script_cve_id("CVE-2004-0078");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2004-043-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-043-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.405607");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt' package(s) announced via the SSA:2004-043-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mutt is a text-based program for reading electronic mail.

New mutt packages are available for Slackware 8.1, 9.0, 9.1,
and -current. These have been upgraded to version 1.4.2i to
fix a buffer overflow that could lead to a machine compromise.
All sites using mutt should upgrade to the new mutt package.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Thu Feb 12 10:00:37 PST 2004
patches/packages/mutt-1.4.2i-i486-1.tgz: Upgraded to mutt-1.4.2i.
 This fixes an overflow that is a potential security hole. Here's the
 information from www.mutt.org:
 'Mutt 1.4.2 was released on February 11, 2004. This version fixes a buffer
 overflow that can be triggered by incoming messages. There are reports
 about spam that has actually triggered this problem and crashed mutt. It
 is recommended that users of mutt versions prior to 1.4.2 upgrade to this
 version, or apply the patch included below.'
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mutt' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware current.");

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

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"mutt", ver:"1.4.2i-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mutt", ver:"1.4.2i-i386-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mutt", ver:"1.4.2i-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mutt", ver:"1.4.2i-i486-1", rls:"SLKcurrent"))) {
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

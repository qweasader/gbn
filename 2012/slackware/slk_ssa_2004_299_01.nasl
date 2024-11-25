# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53903");
  script_cve_id("CVE-2004-0492", "CVE-2004-0885");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2004-299-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-299-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.661410");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the SSA:2004-299-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New apache and mod_ssl packages are available for Slackware 8.1, 9.0, 9.1,
10.0, and -current to fix security issues. Apache has been upgraded to
version 1.3.32 which fixes a heap-based buffer overflow in mod_proxy.
mod_ssl was upgraded from version mod_ssl-2.8.19-1.3.31 to version
2.8.21-1.3.32 which corrects a flaw allowing a client to use a cipher
which the server does not consider secure enough.

A new PHP package (php-4.3.9) is also available for all of these platforms.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]
 [link moved to references]


Here are the details from the Slackware 10.0 ChangeLog:
+--------------------------+
patches/packages/apache-1.3.32-i486-1.tgz: Upgraded to apache-1.3.32.
 This addresses a heap-based buffer overflow in mod_proxy by rejecting
 responses from a remote server with a negative Content-Length. The
 flaw could crash the Apache child process, or possibly allow code to
 be executed as the Apache user (but only if mod_proxy is actually in
 use on the server).
 For more details, see:
 [link moved to references]
 (* Security fix *)
patches/packages/mod_ssl-2.8.21_1.3.32-i486-1.tgz:
 Upgraded to mod_ssl-2.8.21-1.3.32.
 Don't allow clients to bypass cipher requirements, possibly negotiating
 a connection that the server does not consider secure enough.
 For more details, see:
 [link moved to references]
 (* Security fix *)
patches/packages/php-4.3.9-i486-1.tgz: Upgraded to php-4.3.9.
+--------------------------+");

  script_tag(name:"affected", value:"'apache' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.32-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.21_1.3.32-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.9-i486-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.32-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.21_1.3.32-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.9-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.32-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.21_1.3.32-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.9-i386-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.32-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.21_1.3.32-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.9-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.32-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.21_1.3.32-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.9-i486-1", rls:"SLKcurrent"))) {
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

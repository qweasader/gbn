# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58262");
  script_cve_id("CVE-2007-1001");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-03-06T05:05:53+0000");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2007-127-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2007-127-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.470053");
  script_xref(name:"URL", value:"http://www.php.net");
  script_xref(name:"URL", value:"http://www.php.net/releases/4_4_7.php");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_2.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2007-127-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 10.2, 11.0, and -current
to improve the stability and security of PHP. Quite a few bugs were
fixed -- please see [link moved to references] for a detailed list.
All sites that use PHP are encouraged to upgrade. Please note that
we haven't tested all PHP applications for backwards compatibility
with this new upgrade, so you should have the old package on hand
just in case.

Both PHP 4.4.7 and PHP 5.2.2 updates have been provided.


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
extra/php5/php-5.2.2-i486-1_slack11.0.tgz:
 Upgraded to php-5.2.2.
 This fixes bugs and improves security.
 For more details, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/php-4.4.7-i486-1_slack11.0.tgz:
 Upgraded to php-4.4.7.
 This fixes bugs and improves security.
 For more details, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 10.2, Slackware 11.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.7-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.2-i486-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.7-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.2-i486-1_slack11.0", rls:"SLK11.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.7-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.2-i486-1", rls:"SLKcurrent"))) {
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

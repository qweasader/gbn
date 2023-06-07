# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58309");
  script_cve_id("CVE-2007-1887", "CVE-2007-1900", "CVE-2007-2756", "CVE-2007-2872");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2007-152-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2007-152-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.482863");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_3.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the SSA:2007-152-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php5 packages are available for Slackware 10.2, 11.0, and -current to
fix security issues. PHP5 was considered a test package in Slackware 10.2,
and an 'extra' package in Slackware 11.0. If you are currently running
PHP4 you may wish to stick with that, as upgrading to PHP5 will probably
require changes to your system's configuration and/or web code.

More details about the issues affecting Slackware's PHP5 may be found in
the Common Vulnerabilities and Exposures (CVE) database:

 [link moved to references]
 [link moved to references]
 [link moved to references]

One CVE-issued vulnerability (CVE-2007-1887) does not affect Slackware as
we do not ship an unbundled sqlite2 library.


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
extra/php5/php-5.2.3-i486-1_slack11.0.tgz:
Upgraded to php-5.2.3.
 Here's some basic information about the release from php.net:
 'This release continues to improve the security and the stability of the
 5.X branch as well as addressing two regressions introduced by the
 previous 5.2 releases. These regressions relate to the timeout handling
 over non-blocking SSL connections and the lack of HTTP_RAW_POST_DATA in
 certain conditions. All users are encouraged to upgrade to this release.'
 For more complete information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php5' package(s) on Slackware 10.2, Slackware 11.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.3-i486-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.3-i486-1_slack11.0", rls:"SLK11.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.3-i486-1", rls:"SLKcurrent"))) {
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

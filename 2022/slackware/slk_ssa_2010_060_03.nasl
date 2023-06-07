# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2010.060.03");
  script_cve_id("CVE-2010-0001");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2010-060-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2010-060-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.365880");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gzip' package(s) announced via the SSA:2010-060-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gzip packages are available for Slackware 13.0 (64-bit) and -current to
fix a security issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware64 13.0 ChangeLog:
+--------------------------+
patches/packages/gzip-1.4-x86_64-1_slack13.0.tgz: Upgraded.
 gzip -d could segfault and/or clobber the stack, possibly leading to
 arbitrary code execution. This affects x86_64 but not 32-bit systems.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gzip' package(s) on Slackware 13.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gzip", ver:"1.4-x86_64-1_slack13.0", rls:"SLK13.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gzip", ver:"1.4-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gzip", ver:"1.4-x86_64-1", rls:"SLKcurrent"))) {
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

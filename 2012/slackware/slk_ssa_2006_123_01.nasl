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
  script_oid("1.3.6.1.4.1.25623.1.0.56691");
  script_cve_id("CVE-2006-1526");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-123-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.1|10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-123-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.437110");
  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/xorg/2006-May/015136.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg' package(s) announced via the SSA:2006-123-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xorg and xorg-devel packages are available for Slackware 10.1, 10.2,
and -current to fix a security issue. A typo in the X render extension
in X.Org 6.8.0 or later allows an X client to crash the server and
possibly to execute arbitrary code as the X server user (typically this
is 'root'.)

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]

The advisory from X.Org may be found here:

 [link moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/x11-6.8.2-i486-5.tgz:
 Patched with x11r6.9.0-mitri.diff and recompiled.
 A typo in the X render extension allows an X client to crash the server
 and possibly to execute arbitrary code as the X server user (typically
 this is 'root'.)
 The CVE entry for this issue may be found here:
 [link moved to references]
 The advisory from X.Org may be found here:
 [link moved to references]
 (* Security fix *)
patches/packages/x11-devel-6.8.2-i486-5.tgz:
 Patched and recompiled libXrender.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xorg' package(s) on Slackware 10.1, Slackware 10.2, Slackware current.");

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

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.1-i486-5", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-devel", ver:"6.8.1-i486-5", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.2-i486-5", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-devel", ver:"6.8.2-i486-5", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.9.0-i486-4", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-devel", ver:"6.9.0-i486-4", rls:"SLKcurrent"))) {
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

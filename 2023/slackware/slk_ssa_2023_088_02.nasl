# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.088.02");
  script_cve_id("CVE-2023-1393");
  script_tag(name:"creation_date", value:"2023-03-30 04:19:38 +0000 (Thu, 30 Mar 2023)");
  script_version("2023-04-10T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-10 10:19:20 +0000 (Mon, 10 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 14:42:00 +0000 (Fri, 07 Apr 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-088-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-088-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.675802");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2023-March/003374.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-1393");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the SSA:2023-088-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xorg-server packages are available for Slackware 15.0 and -current to
fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/xorg-server-1.20.14-i586-8_slack15.0.txz: Rebuilt.
 [PATCH] composite: Fix use-after-free of the COW.
 Fix use-after-free that can lead to local privileges elevation on systems
 where the X server is running privileged and remote code execution for ssh
 X forwarding sessions.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/xorg-server-xephyr-1.20.14-i586-8_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xnest-1.20.14-i586-8_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xvfb-1.20.14-i586-8_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xwayland-21.1.4-i586-7_slack15.0.txz: Rebuilt.
 [PATCH] composite: Fix use-after-free of the COW.
 Fix use-after-free that can lead to local privileges elevation on systems
 where the X server is running privileged and remote code execution for ssh
 X forwarding sessions.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Slackware 15.0, Slackware current.");

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

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-x86_64-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-i586-7_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-x86_64-7_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.8-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.8-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.8-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.8-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.8-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.8-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.8-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.8-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"23.1.1-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"23.1.1-x86_64-1", rls:"SLKcurrent"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.53892");
  script_cve_id("CVE-2003-0244");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2003-168-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK9\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2003-168-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.522012");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernels' package(s) announced via the SSA:2003-168-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Precompiled Linux 2.4.21 kernels and source packages are now available for
Slackware 9.0 and -current. These provide an improved version of the
ptrace fix that had been applied to 2.4.20 in Slackware 9.0 (for example,
command line options now appear correctly when root does 'ps ax'), and
fix a potential denial of service problem with netfilter.

Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Tue Jun 17 19:41:55 PDT 2003
New precompiled Linux 2.4.21 kernels and source packages are now available
 for Slackware 9.0. These fix a few problems with the ptrace patch used
 with the 2.4.20 kernel, and add a few extra drivers (like Silicon Image
 Serial-ATA support). The new kernel also fixes a number of security
 issues, such as a routing cache problem in 2.4.20 and earlier can allow
 an attacker to cause hash collisions in the prerouting chain that consume
 CPU resources resulting in a denial-of-service (CAN-2003-0244).
patches/packages/kernel-headers-2.4.21-i386-1.tgz: Upgraded to Linux
 2.4.21 kernel headers.
patches/packages/kernel-ide-2.4.21-i486-1.tgz: Upgraded to Linux 2.4.21.
patches/packages/kernel-modules-2.4.21-i486-1.tgz: Upgraded kernel modules
 to Linux 2.4.21.
patches/packages/kernel-modules-2.4.21_xfs-i486-1.tgz: Upgraded the
 XFS-patched kernel modules package to Linux 2.4.21-xfs. These are needed
 for the xfs.i kernel.
patches/packages/kernel-source-2.4.21-noarch-1.tgz: Upgraded to Linux
 2.4.21 source.
patches/kernels/*: Upgraded to Linux 2.4.21.
(* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernels' package(s) on Slackware 9.0.");

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

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.21-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.21-i486-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.21-i486-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.21_xfs-i486-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.21-noarch-1", rls:"SLK9.0"))) {
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

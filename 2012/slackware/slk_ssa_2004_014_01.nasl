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
  script_oid("1.3.6.1.4.1.25623.1.0.53949");
  script_cve_id("CVE-2003-0988");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2004-014-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-014-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.442811");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdepim' package(s) announced via the SSA:2004-014-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kdepim packages are available for Slackware 9.0 and 9.1 to
fix a security issue with .VCF file handling. For Slackware -current,
a complete upgrade to kde-3.1.5 is available.


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Wed Jan 14 11:58:58 PST 2004
patches/packages/kdepim-3.1.4-i486-2.tgz: Recompiled with security patch
 post-3.1.4-kdepim-kfile-plugins.diff. From the KDE advisory:

 The KDE team has found a buffer overflow in the file information reader
 of VCF files. A carefully crafted .VCF file potentially enables local
 attackers to compromise the privacy of a victim's data or execute
 arbitrary commands with the victim's privileges.
 By default, file information reading is disabled for remote files.
 However, if previews are enabled for remote files, remote attackers may
 be able to compromise the victim's account.

 For more details, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kdepim' package(s) on Slackware 9.0, Slackware 9.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"kdebase", ver:"3.1.3-i386-2", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kdepim", ver:"3.1.3-i386-2", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kdepim", ver:"3.1.4-i486-2", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"arts", ver:"1.1.5-i486-1", rls:"SLKcurrent"))) {
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

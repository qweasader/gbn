# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853124");
  script_version("2022-08-05T10:11:37+0000");
  script_cve_id("CVE-2020-11722");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-05 10:11:37 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-25 00:15:00 +0000 (Sat, 25 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-25 03:01:02 +0000 (Sat, 25 Apr 2020)");
  script_name("openSUSE: Security Advisory for crawl (openSUSE-SU-2020:0549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0549-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00037.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crawl'
  package(s) announced via the openSUSE-SU-2020:0549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for crawl fixes the following issues:

  * CVE-2020-11722: Fixed a remote code evaluation issue with lua loadstring
  (boo#1169381)

  Update to version 0.24.0

  * Vampire species simplified

  * Thrown weapons streamlined

  * Fedhas reimagined

  * Sif Muna reworked


  Update to version 0.23.2

  * Trap system overhaul

  * New Gauntlet portal to replace Labyrinths

  * Nemelex Xobeh rework

  * Nine unrandarts reworked and the new 'Rift' unrandart added

  * Support for seeded dungeon play

  * build requires python and python-pyYAML

  Update to 0.22.0

  * Player ghosts now only appear in sealed ghost vaults

  * New spell library interface

  * User interface revamp for Tiles and WebTiles


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-549=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-549=1");

  script_tag(name:"affected", value:"'crawl' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"crawl", rpm:"crawl~0.24.0~lp151.3.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-debugsource", rpm:"crawl-debugsource~0.24.0~lp151.3.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-sdl", rpm:"crawl-sdl~0.24.0~lp151.3.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-sdl-debuginfo", rpm:"crawl-sdl-debuginfo~0.24.0~lp151.3.3.2", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crawl-data", rpm:"crawl-data~0.24.0~lp151.3.3.2", rls:"openSUSELeap15.1"))) {
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
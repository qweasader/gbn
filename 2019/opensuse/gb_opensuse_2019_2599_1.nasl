# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852796");
  script_version("2021-09-07T10:01:34+0000");
  script_cve_id("CVE-2019-18622");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 22:15:00 +0000 (Tue, 14 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-12-02 03:00:48 +0000 (Mon, 02 Dec 2019)");
  script_name("openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2019:2599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:2599-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2019:2599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes the following issues:

  phpMyAdmin was updated to 4.9.2:

  * CVE-2019-18622: SQL injection in Designer feature (boo#1157614)

  * Fixes for 'Failed to set session cookie' error

  * Advisor with MySQL 8.0.3 and newer

  * Fix PHP deprecation errors

  * Fix a situation where exporting users after a delete query could remove
  users

  * Fix incorrect 'You do not have privileges to manipulate with the users!'
  warning

  * Fix copying a database's privileges and several other problems moving
  columns with MariaDB

  * Fix for phpMyAdmin not selecting all the values when using shift-click
  to select during Export

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2599=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2599=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2019-2599=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-2599=1");

  script_tag(name:"affected", value:"'phpMyAdmin' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~4.9.2~lp150.37.1", rls:"openSUSELeap15.0"))) {
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

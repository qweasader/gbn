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
  script_oid("1.3.6.1.4.1.25623.1.0.852561");
  script_version("2021-09-07T13:01:38+0000");
  script_cve_id("CVE-2019-3820");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-19 17:46:00 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-06-19 02:00:57 +0000 (Wed, 19 Jun 2019)");
  script_name("openSUSE: Security Advisory for gnome-shell (openSUSE-SU-2019:1582-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1582-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-shell'
  package(s) announced via the openSUSE-SU-2019:1582-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnome-shell fixes the following issues:

  Security issue fixed:

  - CVE-2019-3820: Fixed a partial lock screen bypass (bsc#1124493).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1582=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1582=1");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-lang", rpm:"gnome-shell-lang~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-browser-plugin", rpm:"gnome-shell-browser-plugin~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>gnome-shell-browser-plugin-debuginfo", rpm:"<br>gnome-shell-browser-plugin-debuginfo~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-calendar", rpm:"gnome-shell-calendar~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-calendar-debuginfo", rpm:"gnome-shell-calendar-debuginfo~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debuginfo", rpm:"gnome-shell-debuginfo~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debugsource", rpm:"gnome-shell-debugsource~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-devel", rpm:"gnome-shell-devel~3.26.2+20180130.0d9c74212~lp150.3.16.1", rls:"openSUSELeap15.0"))) {
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

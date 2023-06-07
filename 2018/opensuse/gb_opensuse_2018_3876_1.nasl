# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852143");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2018-11-26 15:08:53 +0100 (Mon, 26 Nov 2018)");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2018:3876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"openSUSE-SU", value:"2018:3876-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the openSUSE-SU-2018:3876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox fixes the following issues:

  virtualbox was updated to version 5.2.22 (released November 09 2018 by
  Oracle).

  Security issues fixed:

  - Fixed a guest-to-host escape via the e1000 virtual network driver
  (bsc#1115041).


  Non-security issues fixed:

  - Audio: Fixed a regression in the Core Audio backend causing a hang when
  returning from host sleep when processing input buffers.

  - Audio: Fixed a potential crash in the HDA emulation if a stream has no
  valid mixer sink attached.

  - Linux Additions: Disable 3D for recent guests using Wayland (bug #18116).

  - Linux Additions: Fix for rebuilding kernel modules for new kernels on
  RPM guests.

  - Linux Additions: Further fixes for Linux 4.19.

  - Linux Additions: Fixed errors rebuilding initrd files with dracut on EL
  6 (bug 18055#).

  - Linux Additions: Fixed 5.2.20 regression: guests not remembering the
  screen size after shutdown and restart (bug #18078).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1443=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1443=1");

  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.2.22_k4.4.162_78~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.2.22_k4.4.162_78~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.2.22_k4.4.162_78~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.2.22_k4.4.162_78~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.2.22~63.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox", rpm:"python3-virtualbox~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-virtualbox-debuginfo", rpm:"python3-virtualbox-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.2.22_k4.12.14_lp150.12.25~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>virtualbox-guest-kmp-default-debuginfo", rpm:"<br>virtualbox-guest-kmp-default-debuginfo~5.2.22_k4.12.14_lp150.12.25~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.2.22_k4.12.14_lp150.12.25~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"<br>virtualbox-host-kmp-default-debuginfo", rpm:"<br>virtualbox-host-kmp-default-debuginfo~5.2.22_k4.12.14_lp150.12.25~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.2.22~lp150.4.23.1", rls:"openSUSELeap15.0"))) {
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

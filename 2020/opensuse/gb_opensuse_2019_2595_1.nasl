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
  script_oid("1.3.6.1.4.1.25623.1.0.852872");
  script_version("2021-09-20T08:01:57+0000");
  script_cve_id("CVE-2019-12625", "CVE-2019-12900");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 12:18:00 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"creation_date", value:"2020-01-09 09:39:41 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for clamav (openSUSE-SU-2019:2595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2595-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00078.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the openSUSE-SU-2019:2595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

  Security issue fixed:

  - CVE-2019-12625: Fixed a ZIP bomb issue by adding detection and
  heuristics for zips with overlapping files (bsc#1144504).

  - CVE-2019-12900: Fixed an out-of-bounds write in decompress.c with many
  selectors (bsc#1149458).

  Non-security issues fixed:

  - Added the --max-scantime clamscan option and MaxScanTime clamd
  configuration option (bsc#1144504).

  - Increased the startup timeout of clamd to 5 minutes to cater for the
  grown virus database as a workaround until clamd has learned to talk to
  systemd to extend the timeout as long as needed (bsc#1151839).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2595=1");

  script_tag(name:"affected", value:"'clamav' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7", rpm:"libclamav7~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7-debuginfo", rpm:"libclamav7-debuginfo~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0-debuginfo", rpm:"libclammspack0-debuginfo~0.100.3~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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

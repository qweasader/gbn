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
  script_oid("1.3.6.1.4.1.25623.1.0.852840");
  script_version("2021-08-13T12:00:53+0000");
  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845", "CVE-2019-9511",
                "CVE-2019-9513", "CVE-2019-9516");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-08-13 12:00:53 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 17:50:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:35:30 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for nginx (openSUSE-SU-2019:2120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2120-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx'
  package(s) announced via the openSUSE-SU-2019:2120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nginx fixes the following issues:

  Security issues fixed:

  - CVE-2019-9511: Fixed a denial of service by manipulating the window size
  and stream prioritization (bsc#1145579).

  - CVE-2019-9513: Fixed a denial of service caused by resource loops
  (bsc#1145580).

  - CVE-2019-9516: Fixed a denial of service caused by header leaks
  (bsc#1145582).

  - CVE-2018-16845: Fixed denial of service and memory disclosure via mp4
  module (bsc#1115015).

  - CVE-2018-16843: Fixed excessive memory consumption in HTTP/2
  implementation (bsc#1115022).

  - CVE-2018-16844: Fixed excessive CPU usage via flaw in HTTP/2
  implementation (bsc#1115025).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2120=1");

  script_tag(name:"affected", value:"'nginx' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.14.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.14.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.14.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-source", rpm:"nginx-source~1.14.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-plugin-nginx", rpm:"vim-plugin-nginx~1.14.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
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

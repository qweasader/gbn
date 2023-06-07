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
  script_oid("1.3.6.1.4.1.25623.1.0.852678");
  script_version("2023-03-06T10:19:58+0000");
  script_cve_id("CVE-2019-14523", "CVE-2019-14524");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-06 10:19:58 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 17:46:00 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-08-24 02:00:47 +0000 (Sat, 24 Aug 2019)");
  script_name("openSUSE: Security Advisory for schismtracker (openSUSE-SU-2019:1994-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1994-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'schismtracker'
  package(s) announced via the openSUSE-SU-2019:1994-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for schismtracker fixes the following issues:

  The following security issues were fixed:

  - CVE-2019-14523: Fixed an integer underflow in the Amiga Oktalyzer parser
  (boo#1144266).

  - CVE-2019-14524: Fixed a heap overflow in the MTM loader (boo#1144261).

  The following non-security issues were fixed:

  - Support 15-channel MOD files.

  - Support undocumented MIDI macro characters, and support character p
  (MIDI program) properly.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1994=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1994=1");

  script_tag(name:"affected", value:"'schismtracker' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"schismtracker", rpm:"schismtracker~20190805~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"schismtracker-debuginfo", rpm:"schismtracker-debuginfo~20190805~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"schismtracker-debugsource", rpm:"schismtracker-debugsource~20190805~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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

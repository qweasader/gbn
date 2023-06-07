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
  script_oid("1.3.6.1.4.1.25623.1.0.852616");
  script_version("2023-02-07T12:10:58+0000");
  script_cve_id("CVE-2019-10153");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-02-07 12:10:58 +0000 (Tue, 07 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-02 18:58:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-07-20 02:00:43 +0000 (Sat, 20 Jul 2019)");
  script_name("openSUSE: Security Advisory for fence-agents (openSUSE-SU-2019:1719-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1719-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fence-agents'
  package(s) announced via the openSUSE-SU-2019:1719-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fence-agents version 4.4.0 fixes the following issues:

  Security issue fixed:

  - CVE-2019-10153: Fixed a denial of service via guest VM comments
  (bsc#1137314).

  Non-security issue fixed:

  - Included timestamps when logging (bsc#1049852).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1719=1");

  script_tag(name:"affected", value:"'fence-agents' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"fence-agents", rpm:"fence-agents~4.4.0+git.1558595666.5f79f9e9~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-amt_ws", rpm:"fence-agents-amt_ws~4.4.0+git.1558595666.5f79f9e9~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-debuginfo", rpm:"fence-agents-debuginfo~4.4.0+git.1558595666.5f79f9e9~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-debugsource", rpm:"fence-agents-debugsource~4.4.0+git.1558595666.5f79f9e9~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-devel", rpm:"fence-agents-devel~4.4.0+git.1558595666.5f79f9e9~lp150.2.10.1", rls:"openSUSELeap15.0"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.853133");
  script_version("2020-05-07T07:41:43+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-05-07 07:41:43 +0000 (Thu, 07 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-02 03:00:56 +0000 (Sat, 02 May 2020)");
  script_name("openSUSE: Security Advisory for resource-agents (openSUSE-SU-2020:0585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0585-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'resource-agents'
  package(s) announced via the openSUSE-SU-2020:0585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for resource-agents fixes the following issues:

  - Fixed multiple vulnerabilities related to unsafe tempfile usage.
  (bsc#1146690 bsc#1146691 bsc#1146692 bsc#1146766 bsc#1146776 bsc#1146784
  bsc#1146785 bsc#1146787)

  - Fixed issues where the ocfmon user was created with a default password
  (bsc#1021689, bsc#1146687).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-585=1");

  script_tag(name:"affected", value:"'resource-agents' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ldirectord", rpm:"ldirectord~4.3.0184.6ee15eb2~lp151.3.18.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resource-agents", rpm:"resource-agents~4.3.0184.6ee15eb2~lp151.3.18.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resource-agents-debuginfo", rpm:"resource-agents-debuginfo~4.3.0184.6ee15eb2~lp151.3.18.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resource-agents-debugsource", rpm:"resource-agents-debugsource~4.3.0184.6ee15eb2~lp151.3.18.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitoring-plugins-metadata", rpm:"monitoring-plugins-metadata~4.3.0184.6ee15eb2~lp151.3.18.1", rls:"openSUSELeap15.1"))) {
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
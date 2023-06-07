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
  script_oid("1.3.6.1.4.1.25623.1.0.853068");
  script_version("2022-01-03T03:03:25+0000");
  script_cve_id("CVE-2018-14553", "CVE-2019-11038");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-01-03 03:03:25 +0000 (Mon, 03 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 12:58:00 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-03-11 04:00:50 +0000 (Wed, 11 Mar 2020)");
  script_name("openSUSE: Security Advisory for gd (openSUSE-SU-2020:0332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0332-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gd'
  package(s) announced via the openSUSE-SU-2020:0332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gd fixes the following issues:

  Security issue fixed:

  - CVE-2018-14553: Fixed a null pointer dereference in gdImageClone
  (bsc#1165471).

  - CVE-2019-11038: Fixed an information disclosure in gdImageCreateFromXbm()
  (bsc#1140120).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-332=1");

  script_tag(name:"affected", value:"'gd' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gd", rpm:"gd~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gd-debuginfo", rpm:"gd-debuginfo~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gd-debugsource", rpm:"gd-debugsource~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gd-devel", rpm:"gd-devel~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3", rpm:"libgd3~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3-debuginfo", rpm:"libgd3-debuginfo~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3-32bit", rpm:"libgd3-32bit~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3-32bit-debuginfo", rpm:"libgd3-32bit-debuginfo~2.2.5~lp151.6.6.1", rls:"openSUSELeap15.1"))) {
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
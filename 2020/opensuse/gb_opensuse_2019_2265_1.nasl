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
  script_oid("1.3.6.1.4.1.25623.1.0.852885");
  script_version("2021-08-13T09:00:57+0000");
  script_cve_id("CVE-2019-6471");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-01 13:34:00 +0000 (Fri, 01 Nov 2019)");
  script_tag(name:"creation_date", value:"2020-01-09 09:41:21 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for bind (openSUSE-SU-2019:2265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2265-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-10/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the openSUSE-SU-2019:2265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  Security issue fixed:

  - CVE-2019-6471: Fixed a reachable assert in dispatch.c. (bsc#1138687)

  Non-security issue fixed:

  - bind will no longer rely on /etc/insserv.conf (bsc#1118367, bsc#1118368)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2265=1");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd", rpm:"bind-lwresd~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-lwresd-debuginfo", rpm:"bind-lwresd-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-160", rpm:"libbind9-160~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-160-debuginfo", rpm:"libbind9-160-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns169", rpm:"libdns169~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns169-debuginfo", rpm:"libdns169-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs160", rpm:"libirs160~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs160-debuginfo", rpm:"libirs160-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166", rpm:"libisc166~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166-debuginfo", rpm:"libisc166-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc160", rpm:"libisccc160~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc160-debuginfo", rpm:"libisccc160-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg160", rpm:"libisccfg160~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg160-debuginfo", rpm:"libisccfg160-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres160", rpm:"liblwres160~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres160-debuginfo", rpm:"liblwres160-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel-32bit", rpm:"bind-devel-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-160-32bit", rpm:"libbind9-160-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-160-32bit-debuginfo", rpm:"libbind9-160-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns169-32bit", rpm:"libdns169-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns169-32bit-debuginfo", rpm:"libdns169-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs160-32bit", rpm:"libirs160-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs160-32bit-debuginfo", rpm:"libirs160-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166-32bit", rpm:"libisc166-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166-32bit-debuginfo", rpm:"libisc166-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc160-32bit", rpm:"libisccc160-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc160-32bit-debuginfo", rpm:"libisccc160-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg160-32bit", rpm:"libisccfg160-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg160-32bit-debuginfo", rpm:"libisccfg160-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres160-32bit", rpm:"liblwres160-32bit~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres160-32bit-debuginfo", rpm:"liblwres160-32bit-debuginfo~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.11.2~lp151.11.6.1", rls:"openSUSELeap15.1"))) {
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

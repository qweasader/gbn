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
  script_oid("1.3.6.1.4.1.25623.1.0.852703");
  script_version("2021-09-07T08:01:28+0000");
  script_cve_id("CVE-2019-5481", "CVE-2019-5482");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-09-25 02:00:49 +0000 (Wed, 25 Sep 2019)");
  script_name("openSUSE: Security Advisory for curl (openSUSE-SU-2019:2169-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:2169-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the openSUSE-SU-2019:2169-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

  Security issues fixed:

  - CVE-2019-5481: Fixed FTP-KRB double-free during kerberos FTP data
  transfer (bsc#1149495).

  - CVE-2019-5482: Fixed TFTP small blocksize heap buffer overflow
  (bsc#1149496).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2169=1");

  script_tag(name:"affected", value:"'curl' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel-32bit", rpm:"libcurl-devel-32bit~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit-debuginfo", rpm:"libcurl4-32bit-debuginfo~7.60.0~lp150.2.25.1", rls:"openSUSELeap15.0"))) {
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

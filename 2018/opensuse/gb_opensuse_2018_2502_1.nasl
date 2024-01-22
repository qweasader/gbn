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
  script_oid("1.3.6.1.4.1.25623.1.0.852094");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-10887", "CVE-2018-10888", "CVE-2018-11235", "CVE-2018-15501");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 15:56:00 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-10-26 06:47:24 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for libgit2 (openSUSE-SU-2018:2502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:2502-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00074.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2'
  package(s) announced via the openSUSE-SU-2018:2502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgit2 to version 0.26.5 fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-10887: Fixed an integer overflow which in turn leads to an out
  of bound read, allowing to read the base object, which could be
  exploited by an attacker to cause denial of service (DoS) (bsc#1100613).

  - CVE-2018-10888: Fixed an out-of-bound read while reading a binary delta
  file, which could be exploited by an attacker t ocause a denial of
  service (DoS) (bsc#1100612).

  - CVE-2018-11235: Fixed a remote code execution, which could occur with a
  crafted .gitmodules file (bsc#1095219)

  - CVE-2018-15501: Prevent out-of-bounds reads when processing
  smart-protocol 'ng' packets (bsc#1104641)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-922=1");

  script_tag(name:"affected", value:"libgit2 on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"libgit2-26", rpm:"libgit2-26~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-debuginfo", rpm:"libgit2-26-debuginfo~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-debugsource", rpm:"libgit2-debugsource~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-devel", rpm:"libgit2-devel~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit", rpm:"libgit2-26-32bit~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-32bit-debuginfo", rpm:"libgit2-26-32bit-debuginfo~0.26.6~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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

# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854822");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 14:52:00 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-19 01:03:21 +0000 (Tue, 19 Jul 2022)");
  script_name("openSUSE: Security Advisory for nodejs12 (SUSE-SU-2022:2430-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2430-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/P2RYA6XDX2AFDWM6QPEY5CYBRX4LOPU3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs12'
  package(s) announced via the SUSE-SU-2022:2430-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs12 fixes the following issues:

  - CVE-2022-32212: Fixed DNS rebinding in --inspect via invalid IP
       addresses (bsc#1201328).

  - CVE-2022-32213: Fixed HTTP request smuggling due to flawed parsing of
       Transfer-Encoding (bsc#1201325).

  - CVE-2022-32214: Fixed HTTP request smuggling due to improper delimiting
       of header fields (bsc#1201326).

  - CVE-2022-32215: Fixed HTTP request smuggling due to incorrect parsing of
       multi-line Transfer-Encoding (bsc#1201327).");

  script_tag(name:"affected", value:"'nodejs12' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs12", rpm:"nodejs12~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debuginfo", rpm:"nodejs12-debuginfo~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debugsource", rpm:"nodejs12-debugsource~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-devel", rpm:"nodejs12-devel~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm12", rpm:"npm12~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-docs", rpm:"nodejs12-docs~12.22.12~150200.4.35.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs12", rpm:"nodejs12~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debuginfo", rpm:"nodejs12-debuginfo~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debugsource", rpm:"nodejs12-debugsource~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-devel", rpm:"nodejs12-devel~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm12", rpm:"npm12~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-docs", rpm:"nodejs12-docs~12.22.12~150200.4.35.1", rls:"openSUSELeap15.3"))) {
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
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
  script_oid("1.3.6.1.4.1.25623.1.0.853065");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2019-14553", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-29 22:15:00 +0000 (Thu, 29 Apr 2021)");
  script_tag(name:"creation_date", value:"2020-03-09 04:00:27 +0000 (Mon, 09 Mar 2020)");
  script_name("openSUSE: Security Advisory for ovmf (openSUSE-SU-2020:0314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0314-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf'
  package(s) announced via the openSUSE-SU-2020:0314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

  Security issues fixed:

  - CVE-2019-14563: Fixed a memory corruption caused by insufficient numeric
  truncation (bsc#1163959).

  - CVE-2019-14553: Fixed the TLS certification verification in
  HTTPS-over-IPv6 boot sequences (bsc#1153072).

  - CVE-2019-14559: Fixed a remotely exploitable memory leak in the ARP
  handling code (bsc#1163927).

  - CVE-2019-14575: Fixed an insufficient signature check in the
  DxeImageVerificationHandler (bsc#1163969).

  - Enabled HTTPS-over-IPv6 (bsc#1153072).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-314=1");

  script_tag(name:"affected", value:"'ovmf' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ovmf-2017-git1510945757-b2662641d5", rpm:"ovmf-2017-git1510945757-b2662641d5~lp151.11.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools-2017-git1510945757-b2662641d5", rpm:"ovmf-tools-2017-git1510945757-b2662641d5~lp151.11.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86-64-debug-2017-git1510945757-b2662641d5", rpm:"qemu-ovmf-x86-64-debug-2017-git1510945757-b2662641d5~lp151.11.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-ia32-2017-git1510945757-b2662641d5", rpm:"qemu-ovmf-ia32-2017-git1510945757-b2662641d5~lp151.11.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86-64-2017-git1510945757-b2662641d5", rpm:"qemu-ovmf-x86-64-2017-git1510945757-b2662641d5~lp151.11.3.1", rls:"openSUSELeap15.1"))) {
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

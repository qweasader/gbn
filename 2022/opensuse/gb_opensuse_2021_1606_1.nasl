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
  script_oid("1.3.6.1.4.1.25623.1.0.854376");
  script_version("2022-04-01T03:04:03+0000");
  script_cve_id("CVE-2021-4009", "CVE-2021-4010", "CVE-2021-4011");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-01 03:04:03 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 16:34:00 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:34:01 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for xorg-x11-server (openSUSE-SU-2021:1606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1606-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RT7VTD4IRUBMN3UEKSRY3O2T37GG2HLZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the openSUSE-SU-2021:1606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server fixes the following issues:

  - CVE-2021-4009: The handler for the CreatePointerBarrier request of the
       XFixes extension does not properly validate the request length leading
       to out of bounds memory write. (bsc#1190487)

  - CVE-2021-4010: The handler for the Suspend request of the Screen Saver
       extension does not properly validate the request length leading to out
       of bounds memory write. (bsc#1190488)

  - CVE-2021-4011: The handlers for the RecordCreateContext and
       RecordRegisterClients requests of the Record extension do not properly
       validate the request length leading to out of bounds memory write.
       (bsc#1190489)
  This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debugsource", rpm:"xorg-x11-server-debugsource~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra-debuginfo", rpm:"xorg-x11-server-extra-debuginfo~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-wayland", rpm:"xorg-x11-server-wayland~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-wayland-debuginfo", rpm:"xorg-x11-server-wayland-debuginfo~1.20.3~lp152.8.36.1", rls:"openSUSELeap15.2"))) {
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
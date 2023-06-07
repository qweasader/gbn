# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854030");
  script_version("2022-03-07T03:03:52+0000");
  script_cve_id("CVE-2020-25085", "CVE-2021-3582", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3611");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-03-07 03:03:52 +0000 (Mon, 07 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 19:46:00 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"creation_date", value:"2021-08-03 03:01:40 +0000 (Tue, 03 Aug 2021)");
  script_name("openSUSE: Security Advisory for qemu (openSUSE-SU-2021:2591-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2591-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W3DOLLXJN6UCIAFW2F6437T6CGXJTVQO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:2591-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

     Security issues fixed:

  - CVE-2021-3595: Fixed slirp: invalid pointer initialization may lead to
       information disclosure (tftp) (bsc#1187366)

  - CVE-2021-3592: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (bootp) (bsc#1187364)

  - CVE-2021-3594: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp) (bsc#1187367)

  - CVE-2021-3593: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp6) (bsc#1187365)

  - CVE-2021-3582: Fix possible mremap overflow in the pvrdma (bsc#1187499)

  - CVE-2021-3607: Ensure correct input on ring init (bsc#1187539)

  - CVE-2021-3608: Fix the ring init error flow (bsc#1187538)

  - CVE-2021-3611: Fix intel-hda segmentation fault due to stack overflow
       (bsc#1187529)

  - CVE-2020-25085: Fix out-of-bounds access issue while doing multi block
       SDMA (bsc#1176681)

     Other issues fixed:

  - QEMU BIOS fails to read stage2 loader (on s390x)(bsc#1186290)

  - Fix qemu hang while cancelling migrating hugepage vm (bsc#1185591)");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~3.1.1.1~9.30.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss-debuginfo", rpm:"qemu-audio-oss-debuginfo~3.1.1.1~9.30.2", rls:"openSUSELeap15.3"))) {
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
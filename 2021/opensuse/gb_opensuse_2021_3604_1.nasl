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
  script_oid("1.3.6.1.4.1.25623.1.0.854279");
  script_version("2023-01-05T10:12:14+0000");
  script_cve_id("CVE-2021-3713", "CVE-2021-3748");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-05 10:12:14 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 15:16:00 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2021-11-04 02:02:37 +0000 (Thu, 04 Nov 2021)");
  script_name("openSUSE: Security Advisory for qemu (openSUSE-SU-2021:3604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3604-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VSD5Q5DPWCTYJNLRUS2DHTA3G6VDKLMV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:3604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

     Security issues fixed:

  - CVE-2021-3713: Fix out-of-bounds write in UAS (USB Attached SCSI) device
       emulation (bsc#1189702)

  - CVE-2021-3748: Fix heap use-after-free in virtio_net_receive_rcu
       (bsc#1189938)

     Non-security issues fixed:

  - Add transfer length item in block limits page of scsi vpd (bsc#1190425)

  - Fix qemu crash while deleting xen-block (bsc#1189234)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~4.2.1~11.31.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~4.2.1~11.31.3", rls:"openSUSELeap15.3"))) {
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
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0385.1");
  script_cve_id("CVE-2018-5748");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0385-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0385-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180385-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2018:0385-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvirt provides several fixes.
This security issue was fixed:
- CVE-2018-5748: Prevent resource exhaustion via qemuMonitorIORead()
 method which allowed to cause DoS (bsc#1076500).
These security issues were fixed:
- Add a qemu hook script providing functionality similar to Xen's
 block-dmmd script. (fate#324177)
- schema: Make disk driver name attribute optional. (bsc#1073973)
- virt-create-rootfs: Handle all SLE 12 versions. (bsc#1072887)
- libvirt-guests: Fix the 'stop' operation when action is 'suspend'.
 (bsc#1070130)");

  script_tag(name:"affected", value:"'libvirt' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-debuginfo", rpm:"libvirt-client-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-debuginfo", rpm:"libvirt-daemon-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface-debuginfo", rpm:"libvirt-daemon-driver-interface-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl", rpm:"libvirt-daemon-driver-libxl~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-libxl-debuginfo", rpm:"libvirt-daemon-driver-libxl-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc-debuginfo", rpm:"libvirt-daemon-driver-lxc-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network-debuginfo", rpm:"libvirt-daemon-driver-network-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev-debuginfo", rpm:"libvirt-daemon-driver-nodedev-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter-debuginfo", rpm:"libvirt-daemon-driver-nwfilter-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu-debuginfo", rpm:"libvirt-daemon-driver-qemu-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret-debuginfo", rpm:"libvirt-daemon-driver-secret-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-debuginfo", rpm:"libvirt-daemon-driver-storage-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-xen", rpm:"libvirt-daemon-xen~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-debugsource", rpm:"libvirt-debugsource~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock-debuginfo", rpm:"libvirt-lock-sanlock-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss", rpm:"libvirt-nss~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss-debuginfo", rpm:"libvirt-nss-debuginfo~2.0.0~27.29.1", rls:"SLES12.0SP2"))) {
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

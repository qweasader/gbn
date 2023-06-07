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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0357.1");
  script_cve_id("CVE-2014-3633", "CVE-2014-3640", "CVE-2014-3657", "CVE-2014-7823", "CVE-2014-7840", "CVE-2014-8106");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0357-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150357-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm and libvirt' package(s) announced via the SUSE-SU-2015:0357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This collective update for KVM and libvirt provides fixes for security and non-security issues.

kvm:

 * Fix NULL pointer dereference because of uninitialized UDP socket.
 (bsc#897654, CVE-2014-3640)
 * Fix performance degradation after migration. (bsc#878350)
 * Fix potential image corruption due to missing FIEMAP_FLAG_SYNC flag
 in FS_IOC_FIEMAP ioctl. (bsc#908381)
 * Add validate hex properties for qdev. (bsc#852397)
 * Add boot option to do strict boot (bsc#900084)
 * Add query-command-line-options QMP command. (bsc#899144)
 * Fix incorrect return value of migrate_cancel. (bsc#843074)
 * Fix insufficient parameter validation during ram load. (bsc#905097,
 CVE-2014-7840)
 * Fix insufficient blit region checks in qemu/cirrus. (bsc#907805,
 CVE-2014-8106)

libvirt:

 * Fix security hole with migratable flag in dumpxml. (bsc#904176,
 CVE-2014-7823)
 * Fix domain deadlock. (bsc#899484, CVE-2014-3657)
 * Use correct definition when looking up disk in qemu blkiotune.
 (bsc#897783, CVE-2014-3633)
 * Fix undefined symbol when starting virtlockd. (bsc#910145)
 * Add '-boot strict' to qemu's commandline whenever possible.
 (bsc#900084)
 * Add support for 'reboot-timeout' in qemu. (bsc#899144)
 * Increase QEMU's monitor timeout to 30sec. (bsc#911742)
 * Allow setting QEMU's migration max downtime any time. (bsc#879665)

Security Issues:

 * CVE-2014-7823
 * CVE-2014-3657
 * CVE-2014-3633
 * CVE-2014-3640
 * CVE-2014-7840
 * CVE-2014-8106");

  script_tag(name:"affected", value:"'kvm and libvirt' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~0.21.4", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~0.21.5", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.0.5.9~0.19.6", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.0.5.9~0.19.6", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-32bit", rpm:"libvirt-client-32bit~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-32bit", rpm:"libvirt-client-32bit~1.0.5.9~0.19.5", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~1.0.5.9~0.19.6", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.0.5.9~0.19.6", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~1.0.5.9~0.19.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~1.0.5.9~0.19.6", rls:"SLES11.0SP3"))) {
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

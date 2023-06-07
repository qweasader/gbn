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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3463.1");
  script_cve_id("CVE-2021-37600");
  script_tag(name:"creation_date", value:"2021-10-20 02:19:28 +0000 (Wed, 20 Oct 2021)");
  script_version("2021-10-20T02:19:28+0000");
  script_tag(name:"last_modification", value:"2021-10-20 02:19:28 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-12 19:54:00 +0000 (Thu, 12 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3463-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3463-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213463-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the SUSE-SU-2021:3463-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for util-linux fixes the following issues:

CVE-2021-37600: Fixed an integer overflow which could lead to buffer
 overflow in get_sem_elements. (bsc#1188921)

Prevent outdated pam files (bsc#1082293, bsc#1081947#c68).

Do not trim read-only volumes (bsc#1106214).

libmount: To prevent incorrect behavior, recognize more pseudofs and
 netfs (bsc#1122417).

raw.service: Add RemainAfterExit=yes (bsc#1135534).

agetty: Reload issue only if it is really needed (bsc#1085196)

agetty: Return previous response of agetty for special characters
 (bsc#1085196, bsc#1125886)

blockdev: Do not fail --report on kpartx-style partitions on multipath.
 (bsc#1168235)

nologin: Add support for -c to prevent error from su -c. (bsc#1151708)

Avoid triggering autofs in lookup_umount_fs_by_statfs. (bsc#1168389)

libblkid: Do not trigger CDROM autoclose. (bsc#1084671)

Avoid sulogin failing on not existing or not functional console devices.
 (bsc#1175514)

Build with libudev support to support non-root users. (bsc#1169006)

lscpu: avoid segfault on PowerPC systems with valid hardware
 configurations. (bsc#1175623, bsc#1178554, bsc#1178825)

Fix for warning on mounts to CIFS with mount. (SG#57988, bsc#1174942)");

  script_tag(name:"affected", value:"'util-linux' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libblkid1", rpm:"libblkid1~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-32bit", rpm:"libblkid1-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-debuginfo", rpm:"libblkid1-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblkid1-debuginfo-32bit", rpm:"libblkid1-debuginfo-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1", rpm:"libfdisk1~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfdisk1-debuginfo", rpm:"libfdisk1-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1", rpm:"libmount1~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-32bit", rpm:"libmount1-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-debuginfo", rpm:"libmount1-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmount1-debuginfo-32bit", rpm:"libmount1-debuginfo-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1", rpm:"libsmartcols1~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmartcols1-debuginfo", rpm:"libsmartcols1-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1", rpm:"libuuid1~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-32bit", rpm:"libuuid1-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-debuginfo", rpm:"libuuid1-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuuid1-debuginfo-32bit", rpm:"libuuid1-debuginfo-32bit~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libmount", rpm:"python-libmount~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libmount-debuginfo", rpm:"python-libmount-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libmount-debugsource", rpm:"python-libmount-debugsource~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debuginfo", rpm:"util-linux-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-debugsource", rpm:"util-linux-debugsource~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-lang", rpm:"util-linux-lang~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd", rpm:"util-linux-systemd~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd-debuginfo", rpm:"util-linux-systemd-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"util-linux-systemd-debugsource", rpm:"util-linux-systemd-debugsource~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uuidd-debuginfo", rpm:"uuidd-debuginfo~2.29.2~3.24.1", rls:"SLES12.0SP3"))) {
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

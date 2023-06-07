# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122106");
  script_cve_id("CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2213");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:49:18+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:49:18 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-2024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-2024");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-2024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, ofa-2.6.32-200.16.1.el6uek' package(s) announced via the ELSA-2011-2024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-200.16.1.el6uek]
- Revert change to restore DEFAULTKERNEL

[2.6.32-200.15.1.el6uek]
- Add -u parameter to kernel_variant_post to make it work
 properly for uek [orabug 12819958]

[2.6.32-200.14.1.el6uek]
- Restore DEFAULTKERNEL value to kernel-uek [orabug 12819958]

[2.6.32-200.13.1.el6uek]
- make default kernel kernel-uek (Kevin Lyons) [orabug 12803424]

[2.6.32-200.12.1.el6uek]
- SCSI: Fix oops dereferencing queue (Martin K. Petersen) [orabug 12741636]

[2.6.32-200.11.1.el6uek]
- inet_diag: fix inet_diag_bc_audit() (Eric Dumazet) [CVE-2011-2213]

[2.6.32-200.10.8.el6uek]
- block: export blk_{get,put}_queue() (Jens Axboe)
- [SCSI] Fix oops caused by queue refcounting failure (James Bottomley)
- [dm-mpath] maintain reference count for underlying devices (Martin K. Petersen)

[2.6.32-200.10.7.el6uek]
- [net] gre: fix netns vs proto registration ordering {CVE-2011-1767}
- [net] tunnels: fix netns vs proto registration ordering {CVE-2011-1768}
- [rps] don't free rx_queue until netdevice is freed (Dave Kleikamp) [orabug 11071685]

[2.6.32-200.10.6.el6uek]
- Add entropy generation to nics (John Sobecki) [10622900]
- [SCSI] compat_ioct: fix bsg SG_IO [orabug 12732464]
- ipc/sem.c: error path in try_atomic_semop() left spinlock locked

[2.6.32-200.10.5.el6uek]
- update kabi

[2.6.32-200.10.4.el6uek]
- block: Fix double free in blk_integrity_unregister [orabug 12707880]
- block: Make the integrity mapped property a bio flag [orabug 12707880]
- dm mpath: do not fail paths after integrity errors [orabug 12707880]
- dm ioctl: refactor dm_table_complete [orabug 12707880]
- block: Require subsystems to explicitly allocate bio_set integrity mempool [orabug 12707880]
- dm: improve block integrity support [orabug 12707880]
- sd: Update protection mode strings [orabug 12707880]
- [SCSI] fix propagation of integrity errors [orabug 12707880]
- [SCSI] modify change_queue_depth to take in reason why it is being called [orabug 12707880]
- [SCSI] scsi error: have scsi-ml call change_queue_depth to handle QUEUE_FULL [orabug 12707880]
- [SCSI] add queue_depth ramp up code [orabug 12707880]
- [SCSI] scsi_dh: Change the scsidh_activate interface to be asynchronous [orabug 12707880]
- SCSI: Updated RDAC device handler [orabug 12707880]
- [SCSI] scsi_dh: propagate SCSI device deletion [orabug 12707880]
- [SCSI] scsi_dh: fix reference counting in scsi_dh_activate error path [orabug 12707880]
- qla2xxx: Driver update from QLogic [orabug 12707880]
- lpfc 8.3.5.44 driver update from Emulex [orabug 12707880]
- Add Hydra (hxge) support [orabug 12314121]
- update hxge to 1.3.1 [orabug 12314121]
- Hide mwait, TSC invariance and MTRR capability in published CPUID

[2.6.32-200.10.3.el6uek]
- [config] Revert Add some usb devices supported
- [config] make all usb drivers part of the kernel.
- [fs] NFS: Don't SIGBUS if nfs_vm_page_mkwrite races with a cache
 invalidation [orabug ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-uek, ofa-2.6.32-200.16.1.el6uek' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~200.16.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.16.1.el6uek", rpm:"ofa-2.6.32-200.16.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.16.1.el6uekdebug", rpm:"ofa-2.6.32-200.16.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6"))) {
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

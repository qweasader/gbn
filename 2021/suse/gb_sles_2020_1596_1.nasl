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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1596.1");
  script_cve_id("CVE-2020-0543", "CVE-2020-10757", "CVE-2020-12114", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12656");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-15 15:15:00 +0000 (Tue, 15 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1596-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1596-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201596-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1596-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-0543: Fixed a side channel attack against special registers
 which could have resulted in leaking of read values to cores other than
 the one which called it. This attack is known as Special Register Buffer
 Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).

CVE-2020-12652: Fixed an issue which could have allowed local users to
 hold an incorrect lock during the ioctl operation and trigger a race
 condition (bsc#1171218).

CVE-2020-12653: Fixed an issue in the wifi driver which could have
 allowed local users to gain privileges or cause a denial of service
 (bsc#1171195).

CVE-2020-12654: Fixed an issue in he wifi driver which could have
 allowed a remote AP to trigger a heap-based buffer overflow
 (bsc#1171202).

CVE-2020-12656: Fixed an improper handling of certain domain_release
 calls leadingch could have led to a memory leak (bsc#1171219).

CVE-2020-12114: Fixed A pivot_root race condition which could have
 allowed local users to cause a denial of service (panic) by corrupting a
 mountpoint reference counter (bsc#1171098).

CVE-2020-10757: Fixed an issue where remaping hugepage DAX to anon mmap
 could have caused user PTE access (bsc#1172317).

The following non-security bugs were fixed:

can, slip: Protect tty->disc_data in write_wakeup and close with RCU
 (bsc#1171698).

clocksource/drivers/hyper-v: Set TSC clocksource as default w/
 InvariantTSC (bsc#1170620).

Drivers: HV: Send one page worth of kmsg dump over Hyper-V during panic
 (bsc#1170618).

Drivers: hv: vmbus: Fix the issue with freeing up hv_ctl_table_hdr
 (bsc#1170618).

Drivers: hv: vmbus: Get rid of MSR access from vmbus_drv.c (bsc#1170618).

Drivers: hv: vmbus: Make panic reporting to be more useful (bsc#1170618).

Drivers: hv: vmus: Fix the check for return value from kmsg get dump
 buffer (bsc#1170618).

EDAC: Convert to new X86 CPU match macros

ibmvfc: do not send implicit logouts prior to NPIV login (bsc#1169625
 ltc#184611).

ibmvfc: Fix NULL return compiler warning (bsc#1161951 ltc#183551).

KEYS: reaching the keys quotas correctly (bsc#1171689).

NFS: Cleanup if nfs_match_client is interrupted (bsc#1169025).

NFS: Fix a double unlock from nfs_match,get_client (bsc#1169025).

NFS: make nfs_match_client killable (bsc#1169025).

NFS: Unlock requests must never fail (bsc#1172032).

random: always use batched entropy for get_random_u{32,64} (bsc#1164871).

Revert 'ipc,sem: remove uneeded sem_undo_list lock usage in exit_sem()'
 (bsc#1172221).

scsi: ibmvfc: Avoid loss of all paths during SVC node reboot
 (bsc#1161951 ltc#183551).

scsi: ibmvfc: Fix NULL return compiler warning (bsc#1161951 ltc#183551).

x86/dumpstack/64: Handle faults when printing the 'Stack: ' part of an
 OOPS (bsc#1170383).

x86/hyperv: Allow guests to enable InvariantTSC ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.121.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default", rpm:"kgraft-patch-4_4_180-94_121-default~1~4.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_121-default-debuginfo~1~4.5.1", rls:"SLES12.0SP3"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1118.1");
  script_cve_id("CVE-2018-20836", "CVE-2019-19768", "CVE-2019-19770", "CVE-2019-3701", "CVE-2019-9458", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11669", "CVE-2020-8647", "CVE-2020-8649", "CVE-2020-8834", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-11-04T10:11:50+0000");
  script_tag(name:"last_modification", value:"2022-11-04 10:11:50 +0000 (Fri, 04 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 02:22:00 +0000 (Thu, 03 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1118-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201118-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1118-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-8834: KVM on Power8 processors had a conflicting use of
 HSTATE_HOST_R1 to store r1 state in kvmppc_hv_entry plus in
 kvmppc_{save,restore}_tm, leading to a stack corruption. Because of
 this, an attacker with the ability to run code in kernel space of a
 guest VM can cause the host kernel to panic (bnc#1168276).

CVE-2020-11494: An issue was discovered in slc_bump in
 drivers/net/can/slcan.c, which allowed attackers to read uninitialized
 can_frame data, potentially containing sensitive information from kernel
 stack memory, if the configuration lacks CONFIG_INIT_STACK_ALL
 (bnc#1168424).

CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks
 validation of an sk_family field, which might allow attackers to trigger
 kernel stack corruption via crafted system calls (bnc#1167629).

CVE-2019-9458: In the video driver there was a use after free due to a
 race condition. This could lead to local escalation of privilege with no
 additional execution privileges needed (bnc#1168295).

CVE-2019-3701: Fixed an issue in can_can_gw_rcv, which could cause a
 system crash (bnc#1120386).

CVE-2019-19770: Fixed a use-after-free in the debugfs_remove function
 (bsc#1159198).

CVE-2020-11669: Fixed an issue where arch/powerpc/kernel/idle_book3s.S
 did not have save/restore functionality for PNV_POWERSAVE_AMR,
 PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR (bnc#1169390).

CVE-2020-8647: There was a use-after-free vulnerability in the
 vc_do_resize function in drivers/tty/vt/vt.c (bnc#1162929).

CVE-2020-8649: There was a use-after-free vulnerability in the
 vgacon_invert_region function in drivers/video/console/vgacon.c
 (bnc#1162931).

CVE-2020-9383: An issue was discovered set_fdc in drivers/block/floppy.c
 leads to a wait_til_ready out-of-bounds read because the FDC index is
 not checked for errors before assigning it (bnc#1165111).

CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function
 in kernel/trace/blktrace.c (bnc#1159285).

CVE-2018-20836: Fixed an issue where a race condition in
 smp_task_timedout() and smp_task_done() could lead to a use-after-free
 (bnc#1134395).

The following non-security bugs were fixed:

ACPICA: Introduce ACPI_ACCESS_BYTE_WIDTH() macro (bsc#1051510).

ACPI: watchdog: Fix gas->access_width usage (bsc#1051510).

ahci: Add support for Amazon's Annapurna Labs SATA controller
 (bsc#1169013).

ALSA: ali5451: remove redundant variable capture_flag (bsc#1051510).

ALSA: core: Add snd_device_get_state() helper (bsc#1051510).

ALSA: core: Replace zero-length array with flexible-array member
 (bsc#1051510).

ALSA: emu10k1: Fix endianness annotations (bsc#1051510).

ALSA: hda/ca0132 - Add Recon3Di quirk to handle integrated sound on EVGA
 X99 Classified motherboard (bsc#1051510).

ALSA: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.13.1", rls:"SLES12.0SP5"))) {
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

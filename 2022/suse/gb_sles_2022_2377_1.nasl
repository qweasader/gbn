# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2377.1");
  script_cve_id("CVE-2020-26541", "CVE-2021-4157", "CVE-2022-1012", "CVE-2022-1679", "CVE-2022-20132", "CVE-2022-20141", "CVE-2022-20154", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33981");
  script_tag(name:"creation_date", value:"2022-07-13 04:32:23 +0000 (Wed, 13 Jul 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2377-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222377-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-29900, CVE-2022-29901: Fixed the RETBLEED attack, a new Spectre
 like Branch Target Buffer attack, that can leak arbitrary kernel
 information (bsc#1199657).

CVE-2022-1679: Fixed a use-after-free in the Atheros wireless driver in
 the way a user forces the ath9k_htc_wait_for_target function to fail
 with some input messages (bsc#1199487).

CVE-2022-20132: Fixed out of bounds read due to improper input
 validation in lg_probe and related functions of hid-lg.c (bsc#1200619).

CVE-2022-1012: Fixed information leak caused by small table perturb size
 in the TCP source port generation algorithm (bsc#1199482).

CVE-2022-33981: Fixed use-after-free in floppy driver (bsc#1200692)

CVE-2022-20141: Fixed a possible use after free due to improper locking
 in ip_check_mc_rcu() (bsc#1200604).

CVE-2021-4157: Fixed an out of memory bounds write flaw in the NFS
 subsystem, related to the replication of files with NFS. A user could
 potentially crash the system or escalate privileges on the system
 (bsc#1194013).

CVE-2022-20154: Fixed a use after free due to a race condition in
 lock_sock_nested of sock.c. This could lead to local escalation of
 privilege with System execution privileges needed (bsc#1200599).

CVE-2020-26541: Enforce the secure boot forbidden signature database
 (aka dbx) protection mechanism. (bsc#1177282)

CVE-2022-2318: Fixed a use-after-free vulnerability in the timer
 handler in net/rose/rose_timer.c that allow attackers to crash the
 system without any privileges (bsc#1201251).

CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed
 multiple potential data leaks with Block and Network devices when using
 untrusted backends (bsc#1200762).

The following non-security bugs were fixed:

audit: fix a race condition with the auditd tracking code (bsc#1197170).

block: bio-integrity: Advance seed correctly for larger interval sizes
 (git-fixes).

bnxt_en: Remove the setting of dev_port (git-fixes).

bonding: fix bond_neigh_init() (git-fixes).

dm crypt: Avoid percpu_counter spinlock contention in crypt_page_alloc()
 (git-fixes).

drbd: fix duplicate array initializer (git-fixes).

drbd: remove assign_p_sizes_qlim (git-fixes).

drbd: use bdev_alignment_offset instead of queue_alignment_offset
 (git-fixes).

drbd: use bdev based limit helpers in drbd_send_sizes (git-fixes).

exec: Force single empty string when argv is empty (bsc#1200571).

ext4: fix bug_on ext4_mb_use_inode_pa (bsc#1200810).

ext4: fix bug_on in __es_tree_search (bsc#1200809).

ext4: fix bug_on in ext4_writepages (bsc#1200872).

ext4: fix overhead calculation to account for the reserved gdt blocks
 (bsc#1200869).

ext4: fix race condition between ext4_write and ext4_convert_inline_data
 (bsc#1200807).

ext4: fix symlink file size not match to ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.103.1", rls:"SLES12.0SP5"))) {
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

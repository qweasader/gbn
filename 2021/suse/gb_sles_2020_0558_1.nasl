# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0558.1");
  script_cve_id("CVE-2019-14615", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16994", "CVE-2019-19036", "CVE-2019-19045", "CVE-2019-19054", "CVE-2019-19318", "CVE-2019-19927", "CVE-2019-19965", "CVE-2020-2732", "CVE-2020-7053", "CVE-2020-8428", "CVE-2020-8648", "CVE-2020-8992");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 15:01:42 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0558-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200558-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:0558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2020-2732: Fixed an issue affecting Intel CPUs where an L2 guest may
 trick the L0 hypervisor into accessing sensitive L1 resources
 (bsc#1163971).

CVE-2020-8992: An issue was discovered in ext4_protect_reserved_inode in
 fs/ext4/block_validity.c that allowed attackers to cause a soft lockup
 via a crafted journal size (bnc#1164069).

CVE-2020-8648: There was a use-after-free vulnerability in the
 n_tty_receive_buf_common function in drivers/tty/n_tty.c (bnc#1162928).

CVE-2020-8428: There was a use-after-free bug in fs/namei.c, which
 allowed local users to cause a denial of service or possibly obtain
 sensitive information from kernel memory (bnc#1162109).

CVE-2020-7053: There was a use-after-free (write) in the
 i915_ppgtt_close function in drivers/gpu/drm/i915/i915_gem_gtt.c
 (bnc#1160966).

CVE-2019-19045: A memory leak in
 drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c allowed attackers to
 cause a denial of service (memory consumption) by triggering
 mlx5_vector2eqn() failures (bnc#1161522).

CVE-2019-16994: A memory leak existed in sit_init_net() in
 net/ipv6/sit.c which might have caused denial of service (bnc#1161523).

CVE-2019-19054: A memory leak in the cx23888_ir_probe() function in
 drivers/media/pci/cx23885/cx23888-ir.c allowed attackers to cause a
 denial of service (memory consumption) by triggering kfifo_alloc()
 failures (bnc#1161518).

CVE-2019-14896: A heap overflow was found in the add_ie_rates() function
 of the Marvell Wifi Driver (bsc#1157157).

CVE-2019-14897: A stack overflow was found in the
 lbs_ibss_join_existing() function of the Marvell Wifi Driver
 (bsc#1157155).

CVE-2019-19318: Mounting a crafted btrfs image twice could have caused a
 use-after-free (bnc#1158026).

CVE-2019-19036: An issue discovered in btrfs_root_node in
 fs/btrfs/ctree.c allowed a NULL pointer dereference because
 rcu_dereference(root->node) can be zero (bnc#1157692).

CVE-2019-14615: An information disclosure vulnerability existed due to
 insufficient control flow in certain data structures for some Intel(R)
 Processors (bnc#1160195).

CVE-2019-19965: There was a NULL pointer dereference in
 drivers/scsi/libsas/sas_discover.c because of mishandling of port
 disconnection during discovery, related to a PHY down race condition
 (bnc#1159911).

CVE-2019-19927: Fixed an out-of-bounds read access when mounting a
 crafted f2fs filesystem image and performing some operations, related to
 ttm_put_pages in drivers/gpu/drm/ttm/ttm_page_alloc.c (bnc#1160147).

The following non-security bugs were fixed:
6pack,mkiss: fix possible deadlock (bsc#1051510).

ACPI / APEI: Switch estatus pool to use vmalloc memory (bsc#1051510).

ACPI: fix acpi_find_child_device() invocation in acpi_preset_companion()
 (bsc#1051510).

ACPI: PM: Avoid ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.10.1", rls:"SLES12.0SP5"))) {
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

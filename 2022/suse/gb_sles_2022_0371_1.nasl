# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0371.1");
  script_cve_id("CVE-2018-25020", "CVE-2019-15126", "CVE-2020-27820", "CVE-2021-0920", "CVE-2021-0935", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-33098", "CVE-2021-3564", "CVE-2021-39648", "CVE-2021-39657", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4149", "CVE-2021-4159", "CVE-2021-4197", "CVE-2021-4202", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45486", "CVE-2022-0322", "CVE-2022-0330", "CVE-2022-0435");
  script_tag(name:"creation_date", value:"2022-02-12 03:22:52 +0000 (Sat, 12 Feb 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:55 +0000 (Thu, 07 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0371-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220371-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-0435: Fixed remote stack overflow in net/tipc module that
 validate domain record count on input (bsc#1195254).

CVE-2022-0330: Fixed flush TLBs before releasing backing store
 (bsc#1194880).

CVE-2022-0322: Fixed SCTP issue with account stream padding length for
 reconf chunk (bsc#1194985).

CVE-2021-45486: Fixed information leak inside the IPv4 implementation
 caused by very small hash table (bnc#1194087).

CVE-2021-45095: Fixed refcount leak in pep_sock_accept in
 net/phonet/pep.c (bnc#1193867).

CVE-2021-44733: Fixed a use-after-free exists in drivers/tee/tee_shm.c
 in the TEE subsystem, that could have occurred because of a race
 condition in tee_shm_get_from_id during an attempt to free a shared
 memory object (bnc#1193767).

CVE-2021-43976: Fixed a flaw that could allow an attacker (who can
 connect a crafted USB device) to cause a denial of service. (bnc#1192847)

CVE-2021-43975: Fixed a flaw in hw_atl_utils_fw_rpc_wait that could
 allow an attacker (who can introduce a crafted device) to trigger an
 out-of-bounds write via a crafted length value. (bsc#1192845)

CVE-2021-4202: Fixed NFC race condition by adding NCI_UNREG flag
 (bsc#1194529).

CVE-2021-4197: Use cgroup open-time credentials for process migraton
 perm checks (bsc#1194302).

CVE-2021-4159: Fixed kernel ptr leak vulnerability via BPF in
 coerce_reg_to_size (bsc#1194227).

CVE-2021-4149: Fixed btrfs unlock newly allocated extent buffer after
 error (bsc#1194001).

CVE-2021-4083: Fixed a read-after-free memory flaw inside the garbage
 collection for Unix domain socket file handlers when users call close()
 and fget() simultaneouslyand can potentially trigger a race condition
 (bnc#1193727).

CVE-2021-4002: Fixed a missing TLB flush that could lead to leak or
 corruption of data in hugetlbfs. (bsc#1192946)

CVE-2021-39657: Fixed out of bounds read due to a missing bounds check
 in ufshcd_eh_device_reset_handler of ufshcd.c. This could lead to local
 information disclosure with System execution privileges needed
 (bnc#1193864).

CVE-2021-39648: Fixed possible disclosure of kernel heap memory due to a
 race condition in gadget_dev_desc_UDC_show of configfs.c. This could
 lead to local information disclosure with System execution privileges
 needed. User interaction is not needed for exploitation (bnc#1193861).

CVE-2021-3564: Fixed double-free memory corruption in the Linux kernel
 HCI device initialization subsystem that could have been used by
 attaching malicious HCI TTY Bluetooth devices. A local user could use
 this flaw to crash the system (bnc#1186207).

CVE-2021-33098: Fixed a potential denial of service in Intel(R) Ethernet
 ixgbe driver due to improper input validation. (bsc#1192877)

CVE-2021-28715: Fixed issue with xen/netback to do not queue ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.88.1", rls:"SLES12.0SP4"))) {
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

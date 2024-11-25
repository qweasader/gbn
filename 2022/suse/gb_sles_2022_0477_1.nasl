# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0477.1");
  script_cve_id("CVE-2018-25020", "CVE-2019-0136", "CVE-2020-35519", "CVE-2021-0935", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28715", "CVE-2021-33098", "CVE-2021-3564", "CVE-2021-39648", "CVE-2021-39657", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4149", "CVE-2021-4155", "CVE-2021-4197", "CVE-2021-4202", "CVE-2021-43976", "CVE-2021-45095", "CVE-2021-45485", "CVE-2021-45486", "CVE-2022-0330");
  script_tag(name:"creation_date", value:"2022-02-18 03:25:48 +0000 (Fri, 18 Feb 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 14:23:35 +0000 (Thu, 07 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0477-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0477-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220477-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0477-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2018-25020: Fixed an overflow in the BPF subsystem due to a
 mishandling of a long jump over an instruction sequence where inner
 instructions require substantial expansions into multiple BPF
 instructions. This affects kernel/bpf/core.c and net/core/filter.c
 (bnc#1193575).

CVE-2019-0136: Fixed insufficient access control in the Intel(R)
 PROSet/Wireless WiFi Software driver that may have allowed an
 unauthenticated user to potentially enable denial of service via
 adjacent access (bnc#1193157).

CVE-2020-35519: Fixed out-of-bounds memory access in x25_bind in
 net/x25/af_x25.c. A bounds check failure allowed a local attacker with a
 user account on the system to gain access to out-of-bounds memory,
 leading to a system crash or a leak of internal kernel information
 (bnc#1183696).

CVE-2021-0935: Fixed possible out of bounds write in ip6_xmit of
 ip6_output.c due to a use after free. This could lead to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bnc#1192032).

CVE-2021-28711: Fixed issue with xen/blkfront to harden blkfront against
 event channel storms (XSA-391) (bsc#1193440).

CVE-2021-28712: Fixed issue with xen/netfront to harden netfront against
 event channel storms (XSA-391) (bsc#1193440).

CVE-2021-28713: Fixed issue with xen/console to harden hvc_xen against
 event channel storms (XSA-391) (bsc#1193440).

CVE-2021-28715: Fixed issue with xen/netback to do not queue unlimited
 number of packages (XSA-392) (bsc#1193442).

CVE-2021-33098: Fixed improper input validation in the Intel(R) Ethernet
 ixgbe driver that may have allowed an authenticated user to potentially
 cause denial of service via local access (bnc#1192877).

CVE-2021-3564: Fixed double-free memory corruption in the Linux kernel
 HCI device initialization subsystem that could have been used by
 attaching malicious HCI TTY Bluetooth devices. A local user could use
 this flaw to crash the system (bnc#1186207).

CVE-2021-39648: Fixed possible disclosure of kernel heap memory due to a
 race condition in gadget_dev_desc_UDC_show of configfs.c. This could
 lead to local information disclosure with System execution privileges
 needed. User interaction is not needed for exploitation (bnc#1193861).

CVE-2021-39657: Fixed out of bounds read due to a missing bounds check
 in ufshcd_eh_device_reset_handler of ufshcd.c. This could lead to local
 information disclosure with System execution privileges needed
 (bnc#1193864).

CVE-2021-4002: Fixed incorrect TLBs flush in hugetlbfs after
 huge_pmd_unshare (bsc#1192946).

CVE-2021-4083: Fixed a read-after-free memory flaw inside the garbage
 collection for Unix domain socket file handlers when users call close()
 and fget() simultaneouslyand can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.164.1", rls:"SLES12.0SP2"))) {
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

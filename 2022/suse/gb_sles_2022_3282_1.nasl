# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3282.1");
  script_cve_id("CVE-2020-36516", "CVE-2021-4203", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-21385", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-29581", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-36879");
  script_tag(name:"creation_date", value:"2022-09-16 04:59:03 +0000 (Fri, 16 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-17 03:19:00 +0000 (Sat, 17 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3282-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3282-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223282-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3282-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
 net/xfrm/xfrm_policy.c where a refcount could be dropped twice
 (bnc#1201948).

CVE-2022-3028: Fixed race condition that was found in the IP framework
 for transforming packets (XFRM subsystem) (bnc#1202898).

CVE-2022-2977: Fixed reference counting for struct tpm_chip
 (bsc#1202672).

CVE-2022-29581: Fixed improper update of reference count vulnerability
 in net/sched that allowed a local attacker to cause privilege escalation
 to root (bnc#1199665).

CVE-2022-2639: Fixed an integer coercion error that was found in the
 openvswitch kernel module (bnc#1202154).

CVE-2022-26373: Fixed non-transparent sharing of return predictor
 targets between contexts in some Intel Processors (bnc#1201726).

CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).

CVE-2022-21385: Fixed a flaw in net_rds_alloc_sgs() that allowed
 unprivileged local users to crash the machine (bnc#1202897).

CVE-2022-20369: Fixed possible out of bounds write due to improper input
 validation in v4l2_m2m_querybuf of v4l2-mem2mem.c (bnc#1202347).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bsc#1202346).

CVE-2021-4203: Fixed use-after-free read flaw that was found in
 sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
 SO_PEERGROUPS race with listen() (bnc#1194535).

CVE-2020-36516: Fixed an issue in the mixed IPID assignment method where
 an attacker was able to inject data into or terminate a victim's TCP
 session (bnc#1196616).

The following non-security bugs were fixed:

9p: migrate from sync_inode to filemap_fdatawrite_wbc (bsc#1202528).

ACPI: CPPC: Do not prevent CPPC from working in the future (git-fixes).

Fix releasing of old bundles in xfrm_bundle_lookup() (bsc#1201264
 bsc#1190397 bsc#1199617).

KABI: cgroup: Restore KABI of css_set (bsc#1201610).

KVM: PPC: Book3S HV: Context tracking exit guest context before enabling
 irqs (bsc#1065729).

KVM: arm64: Avoid setting the upper 32 bits of TCR_EL2 and CPTR_EL2
 (bsc#1201442)

KVM: nVMX: Set UMIP bit CR4_FIXED1 MSR when emulating UMIP (bsc#1120716).

KVM: x86: Mark TSS busy during LTR emulation _after_ all fault checks
 (git-fixes).

KVM: x86: Set error code to segment selector on LLDT/LTR non-canonical
 #GP (git-fixes).

PCI: dwc: Deallocate EPC memory on dw_pcie_ep_init() errors (git-fixes).

Revert 'USB: xhci: fix U1/U2 handling for hardware with XHCI_INTEL_HOST
 quirk set' (git-fixes).

Revert 'r8152: adjust the settings about MAC clock speed down for
 RTL8153' (git-fixes).

SUNRPC: Fix READ_PLUS crasher (git-fixes).

SUNRPC: Fix the svc_deferred_event trace class (git-fixes).

USB: new quirk for Dell Gen 2 devices (git-fixes).

USB: serial: io_ti: add Agilent E5805A support (git-fixes).

add Kirk ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.109.1", rls:"SLES12.0SP5"))) {
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

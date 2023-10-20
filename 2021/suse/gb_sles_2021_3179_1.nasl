# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3179.1");
  script_cve_id("CVE-2020-12770", "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-3759", "CVE-2021-38160", "CVE-2021-38166", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-38206", "CVE-2021-38207", "CVE-2021-38209");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:00 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3179-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213179-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3640: Fixed a Use-After-Free vulnerability in function
 sco_sock_sendmsg() in the bluetooth stack (bsc#1188172).

CVE-2021-3653: Missing validation of the `int_ctl` VMCB field and allows
 a malicious L1 guest to enable AVIC support for the L2 guest.
 (bsc#1189399).

CVE-2021-3656: Missing validation of the `virt_ext` VMCB field and
 allows a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and
 VLS for the L2 guest (bsc#1189400).

CVE-2021-3679: A lack of CPU resource in tracing module functionality
 was found in the way user uses trace ring buffer in a specific way. Only
 privileged local users (with CAP_SYS_ADMIN capability) could use this
 flaw to starve the resources causing denial of service (bnc#1189057).

CVE-2021-3732: Mounting overlayfs inside an unprivileged user namespace
 can reveal files (bsc#1189706).

CVE-2021-3739: Fixed a NULL pointer dereference when deleting device by
 invalid id (bsc#1189832 ).

CVE-2021-3743: Fixed OOB Read in qrtr_endpoint_post (bsc#1189883).

CVE-2021-3753: Fixed race out-of-bounds in virtual terminal handling
 (bsc#1190025).

CVE-2021-38160: Data corruption or loss could be triggered by an
 untrusted device that supplies a buf->len value exceeding the buffer
 size in drivers/char/virtio_console.c (bsc#1190117)

CVE-2021-38198: arch/x86/kvm/mmu/paging_tmpl.h incorrectly computes the
 access permissions of a shadow page, leading to a missing guest
 protection page fault (bnc#1189262).

CVE-2021-38204: drivers/usb/host/max3421-hcd.c allowed physically
 proximate attackers to cause a denial of service (use-after-free and
 panic) by removing a MAX-3421 USB device in certain situations
 (bnc#1189291).

CVE-2021-38205: drivers/net/ethernet/xilinx/xilinx_emaclite.c made it
 easier for attackers to defeat an ASLR protection mechanism because it
 prints a kernel pointer (i.e., the real IOMEM pointer) (bnc#1189292).

CVE-2021-38207: drivers/net/ethernet/xilinx/ll_temac_main.c allowed
 remote attackers to cause a denial of service (buffer overflow and
 lockup) by sending heavy network traffic for about ten minutes
 (bnc#1189298).

CVE-2021-38166: Fixed an integer overflow and out-of-bounds write when
 many elements are placed in a single bucket in kernel/bpf/hashtab.c
 (bnc#1189233 ).

CVE-2021-38209: Fixed allowed observation of changes in any net
 namespace via net/netfilter/nf_conntrack_standalone.c (bnc#1189393).

CVE-2021-38206: Fixed NULL pointer dereference in the radiotap parser
 inside the mac80211 subsystem (bnc#1189296).

CVE-2021-34556: Fixed side-channel attack via a Speculative Store Bypass
 via unprivileged BPF program that could have obtain sensitive
 information from kernel memory (bsc#1188983).

CVE-2021-35477: Fixed BPF stack frame pointer which could have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.22.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.22.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.22.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.22.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.22.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.22.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.22.1", rls:"SLES15.0SP3"))) {
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

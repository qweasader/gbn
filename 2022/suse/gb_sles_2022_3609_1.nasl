# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3609.1");
  script_cve_id("CVE-2016-3695", "CVE-2020-16119", "CVE-2020-27784", "CVE-2020-36516", "CVE-2021-4155", "CVE-2021-4203", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-2503", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-2905", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-36879", "CVE-2022-39188", "CVE-2022-39190", "CVE-2022-41218", "CVE-2022-41222", "CVE-2022-41848", "CVE-2022-41849");
  script_tag(name:"creation_date", value:"2022-10-19 04:54:17 +0000 (Wed, 19 Oct 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:07:55 +0000 (Wed, 21 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3609-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3609-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223609-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3609-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-39190: Fixed an issue that was discovered in
 net/netfilter/nf_tables_api.c and could cause a denial of service upon
 binding to an already bound chain (bnc#1203117).

CVE-2022-39188: Fixed race condition in include/asm-generic/tlb.h where
 a device driver can free a page while it still has stale TLB entries
 (bnc#1203107).

CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
 net/xfrm/xfrm_policy.c where a refcount could be dropped twice
 (bnc#1201948).

CVE-2022-3028: Fixed race condition that was found in the IP framework
 for transforming packets (XFRM subsystem) (bnc#1202898).

CVE-2022-2977: Fixed reference counting for struct tpm_chip
 (bsc#1202672).

CVE-2022-2905: Fixed tnum_range usage on array range checking for poke
 descriptors (bsc#1202564, bsc#1202860).

CVE-2022-2663: Fixed an issue that was found in nf_conntrack_irc where
 the message handling could be confused and incorrectly matches the
 message (bnc#1202097).

CVE-2022-2639: Fixed an integer coercion error that was found in the
 openvswitch kernel module (bnc#1202154).

CVE-2022-26373: Fixed non-transparent sharing of return predictor
 targets between contexts in some Intel Processors (bnc#1201726).

CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).

CVE-2022-20369: Fixed out of bounds write in v4l2_m2m_querybuf of
 v4l2-mem2mem.c (bnc#1202347).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bsc#1202346).

CVE-2021-4203: Fixed use-after-free read flaw that was found in
 sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
 SO_PEERGROUPS race with listen() (bnc#1194535).

CVE-2021-4155: Fixed a data leak flaw that was found in the way
 XFS_IOC_ALLOCSP IOCTL in the XFS filesystem (bnc#1194272).

CVE-2020-36516: Fixed an issue in the mixed IPID assignment method where
 an attacker was able to inject data into or terminate a victim's TCP
 session (bnc#1196616).

CVE-2020-27784: Fixed a vulnerability that was found in printer_ioctl()
 printer_ioctl() when accessing a deallocated instance (bnc#1202895).

CVE-2016-3695: Fixed an issue inside the einj_error_inject function in
 drivers/acpi/apei/einj.c that allowed users to simulate hardware errors
 and consequently cause a denial of service (bnc#1023051).

CVE-2022-3303: Fixed a race condition in the sound subsystem due to
 improper locking (bnc#1203769).

CVE-2022-41218: Fixed an use-after-free caused by refcount races in
 drivers/media/dvb-core/dmxdev.c (bnc#1202960).

CVE-2022-3239: Fixed an use-after-free in the video4linux driver that
 could lead a local user to able to crash the system or escalate their
 privileges (bnc#1203552).

CVE-2022-41848: Fixed a race condition and resultant use-after-free if a
 physically proximate attacker removes a PCMCIA ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.80.1", rls:"SLES15.0SP3"))) {
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

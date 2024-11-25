# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0152.1");
  script_cve_id("CVE-2019-19083", "CVE-2022-3105", "CVE-2022-3106", "CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3111", "CVE-2022-3112", "CVE-2022-3115", "CVE-2022-3435", "CVE-2022-3564", "CVE-2022-3643", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4662", "CVE-2022-47520", "CVE-2022-47929", "CVE-2023-0266", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-01-27 04:21:47 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:38 +0000 (Mon, 06 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0152-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230152-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2023-0266: Fixed a use-after-free bug led by a missing lock in ALSA.
 (bsc#1207134)

CVE-2022-47929: Fixed a NULL pointer dereference bug in the traffic
 control subsystem which allowed an unprivileged user to trigger a denial
 of service via a crafted traffic control configuration. (bsc#1207237)

CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler
 (bsc#1207036)

CVE-2023-23455: Fixed a bug that could allow attackers to cause a denial
 of service because of type confusion in atm_tc_enqueue. (bsc#1207125)

CVE-2022-3435: Fixed an out-of-bounds read in fib_nh_match() of the file
 net/ipv4/fib_semantics.c (bsc#1204171).

CVE-2022-4662: Fixed a recursive locking violation in usb-storage that
 can cause the kernel to deadlock. (bsc#1206664)

CVE-2022-3115: Fixed a null pointer dereference in malidp_crtc.c caused
 by a lack of checks of the return value of kzalloc. (bsc#1206393)

CVE-2022-47520: Fixed an out-of-bounds read when parsing a Robust
 Security Network (RSN) information element from a Netlink packet.
 (bsc#1206515)

CVE-2022-3112: Fixed a null pointer dereference caused by lacks check
 of the return value of kzalloc() in vdec_helpers.c:amvdec_set_canvases.
 (bsc#1206399)

CVE-2022-3564: Fixed a bug which could lead to use after free, it was
 found in the function l2cap_reassemble_sdu of the file
 net/bluetooth/l2cap_core.c of the component Bluetooth. (bsc#1206073)

CVE-2022-3108: Fixed a bug in kfd_parse_subtype_iolink in
 drivers/gpu/drm/amd/amdkfd/kfd_crat.c where a lack of check of the
 return value of kmemdup() could lead to a NULL pointer dereference.
 (bsc#1206389)

CVE-2019-19083: Fixed a memory leaks in clock_source_create that could
 allow attackers to cause a denial of service (bsc#1157049).

CVE-2022-42328: Fixed a bug which could allow guests to trigger denial
 of service via the netback driver (bsc#1206114).

CVE-2022-42329: Fixed a bug which could allow guests to trigger denial
 of service via the netback driver (bsc#1206113).

CVE-2022-3643: Fixed a bug which could allow guests to trigger NIC
 interface reset/abort/crash via netback driver (bsc#1206113).

CVE-2022-3107: Fixed a null pointer dereference caused by a missing
 check of the return value of kvmalloc_array. (bsc#1206395)

CVE-2022-3111: Fixed a missing release of resource after effective
 lifetime bug caused by a missing free of the WM8350_IRQ_CHG_FAST_RDY in
 wm8350_init_charger. (bsc#1206394)

CVE-2022-3105: Fixed a null pointer dereference caused by a missing
 check of the return value of kmalloc_array. (bsc#1206398)

CVE-2022-3106: Fixed a null pointer dereference caused by a missing
 check of the return value of kmalloc. (bsc#1206397)

The following non-security bugs were fixed:

afs: Fix some tracing details (git-fixes).

arm64: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Availability 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Live Patching 15-SP3, SUSE Linux Enterprise Realtime Extension 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.109.1.150300.18.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~150300.59.109.1", rls:"SLES15.0SP3"))) {
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

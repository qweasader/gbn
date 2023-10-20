# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1550.1");
  script_cve_id("CVE-2017-5753", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16880", "CVE-2018-7191", "CVE-2019-10124", "CVE-2019-11085", "CVE-2019-11091", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11487", "CVE-2019-11811", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12382", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-3846", "CVE-2019-3882", "CVE-2019-5489", "CVE-2019-8564", "CVE-2019-9003", "CVE-2019-9500", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:25:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1550-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1550-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191550-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1550-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-12819: The function __mdiobus_register() called put_device(),
 which triggered a fixed_mdio_bus_init use-after-free. This would cause a
 denial of service. (bsc#1138291)
CVE-2019-12818: The nfc_llcp_build_tlv function in
 net/nfc/llcp_commands.c may return NULL. If the caller does not check
 for this, it will trigger a NULL pointer dereference. This will cause
 denial of service. This used to affect nfc_llcp_build_gb in
 net/nfc/llcp_core.c. (bsc#1138293)
CVE-2019-11477: A sequence of SACKs may have been crafted such that one
 can trigger an integer overflow, leading to a kernel panic.
CVE-2019-11478: It was possible to send a crafted sequence of SACKs
 which will fragment the TCP retransmission queue. An attacker may have
 been able to further exploit the fragmented queue to cause an expensive
 linked-list walk for subsequent SACKs received for that same TCP
 connection.
CVE-2019-11479: An attacker could force the Linux kernel to segment its
 responses into multiple TCP segments. This would drastically increased
 the bandwidth required to deliver the same amount of data. Further, it
 would consume additional resources such as CPU and NIC processing power.
CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and
 possibly escalate privileges was found in the mwifiex kernel module
 while connecting to a malicious wireless network. (bsc#1136424)
CVE-2019-10124: An issue was discovered in the hwpoison implementation
 in mm/memory-failure.c in the Linux kernel. When
 soft_offline_in_use_page() runs
 on a thp tail page after pmd is split, an attacker could cause a denial
 of service (bsc#1130699, CVE-2019-10124).
CVE-2019-12382: An issue was discovered in drm_load_edid_firmware in
 drivers/gpu/drm/drm_edid_load.c in the Linux kernel There was an
 unchecked kstrdup of fwstr, which might allow an attacker to cause a
 denial of service (NULL pointer dereference and system crash).
 (bsc#1136586)
CVE-2019-11487: The Linux kernel allowed page reference count overflow,
 with resultant use-after-free issues, if about 140 GiB of RAM exists.
 This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
 include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c,
 mm/gup.c, and mm/hugetlb.c. It could occur with FUSE requests.
 (bbsc#1133190)
CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux
 kernel allowed local attackers to observe page cache access patterns of
 other processes on the same system, potentially allowing sniffing of
 secret information. (Fixing this affects the output of the fincore
 program.) Limited remote exploitation may be possible, as demonstrated
 by latency differences in accessing public files from an Apache HTTP
 Server. (bsc#1120843)
CVE-2019-11833: fs/ext4/extents.c in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.4.1", rls:"SLES15.0SP1"))) {
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

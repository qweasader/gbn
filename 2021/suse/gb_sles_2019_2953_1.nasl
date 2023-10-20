# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2953.1");
  script_cve_id("CVE-2018-12207", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18805");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 14:47:00 +0000 (Tue, 22 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2953-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2953-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192953-1/");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023735");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7024251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2953-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15-SP1 Azure Kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a
 race condition in the Instruction Fetch Unit of the Intel CPU to cause a
 Machine Exception during Page Size Change, causing the CPU core to be
 non-functional.

 The Linux Kernel kvm hypervisor was adjusted to avoid page size changes in executable pages by splitting / merging huge pages into small pages as More information can be found on [link moved to references] (bnc#1117665 1152505 1155812 1155817 1155945)
CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
 with Transactional Memory support could be used to facilitate
 sidechannel information leaks out of microarchitectural buffers, similar
 to the previously described 'Microarchitectural Data Sampling' attack.

 The Linux kernel was supplemented with the option to disable TSX operation altogether (requiring CPU Microcode updates on older systems)
and better flushing of microarchitectural buffers (VERW).

 The set of options available is described in our TID at [link moved to references] (bnc#1139073 1152497 1152505 1152506).
CVE-2019-18805: There was a signed integer overflow in
 tcp_ack_update_rtt() when userspace writes a very large integer to
 /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading to a denial of service or
 possibly unspecified other impact, aka CID-19fad20d15a6 (bnc#1156187).
CVE-2019-17055: The AF_NFC network module did not enforce CAP_NET_RAW,
 which meant that unprivileged users could create a raw socket
 (bnc#1152782).
CVE-2019-16995: Fix a memory leak in hsr_dev_finalize() if hsr_add_port
 failed to add a port, which may have caused denial of service
 (bsc#1152685).
CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return value, leading to a NULL pointer dereference.
 (bsc#1150457).
CVE-2019-10220: Added sanity checks on the pathnames passed to the user
 space. (bsc#1144903).
CVE-2019-17666: rtlwifi: Fix potential overflow in P2P code
 (bsc#1154372).
CVE-2019-16232: Fix a potential NULL pointer dereference in the Marwell
 libertas driver (bsc#1150465).
CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue
 return value, leading to a NULL pointer dereference. (bsc#1150452).
CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID
 IE, leading to a Buffer Overflow (bsc#1153158).
CVE-2019-17056: The AF_NFC network module did not enforce CAP_NET_RAW,
 which meant that unprivileged users could create a raw socket
 (bsc#1152788).

The following non-security bugs were fixed:
/dev/mem: Bail out upon SIGKILL (git-fixes).

9p: avoid attaching writeback_fid on mmap with type PRIVATE
 (bsc#1051510).

ACPI / CPPC: do not require the _PSD method (bsc#1051510).

ACPI / processor: do ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.29.1", rls:"SLES12.0SP4"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3806.1");
  script_cve_id("CVE-2021-0941", "CVE-2021-20322", "CVE-2021-31916", "CVE-2021-34981", "CVE-2021-37159", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-11-26 03:22:25 +0000 (Fri, 26 Nov 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 19:33:11 +0000 (Tue, 01 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3806-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3806-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213806-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3806-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel for Azure was updated to receive various security and bugfixes.


The following security bugs were fixed:

Unprivileged BPF has been disabled by default to reduce attack surface
 as too many security issues have happened in the past (jsc#SLE-22573)

 You can re-enable via systemctl setting
/proc/sys/kernel/unprivileged_bpf_disabled to 0.
(kernel.unprivileged_bpf_disabled = 0)

CVE-2021-0941: In bpf_skb_change_head of filter.c, there is a possible
 out of bounds read due to a use after free. This could lead to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bnc#1192045).

CVE-2021-31916: An out-of-bounds (OOB) memory write flaw was found in
 list_devices in drivers/md/dm-ioctl.c in the Multi-device driver module
 in the Linux kernel A bound check failure allowed an attacker with
 special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds
 memory leading to a system crash or a leak of internal kernel
 information. The highest threat from this vulnerability is to system
 availability (bnc#1192781).

CVE-2021-20322: Make the ipv4 and ipv6 ICMP exception caches less
 predictive to avoid information leaks about UDP ports in use.
 (bsc#1191790)

CVE-2021-34981: Fixed file refcounting in cmtp when cmtp_attach_device
 fails (bsc#1191961).

CVE-2021-43389: There was an array-index-out-of-bounds flaw in the
 detach_capi_ctr function in drivers/isdn/capi/kcapi.c (bnc#1191958).

CVE-2021-37159: hso_free_net_device in drivers/net/usb/hso.c called
 unregister_netdev without checking for the NETREG_REGISTERED state,
 leading to a use-after-free and a double free (bnc#1188601).

The following non-security bugs were fixed:

ABI: sysfs-kernel-slab: Document some stats (git-fixes).

ALSA: hda: fix general protection fault in azx_runtime_idle (git-fixes).

ALSA: hda: Free card instance properly at probe errors (git-fixes).

ALSA: hda/realtek: Fix mic mute LED for the HP Spectre x360 14
 (git-fixes).

ALSA: hda: Reduce udelay() at SKL+ position reporting (git-fixes).

ALSA: hda: Use position buffer for SKL+ again (git-fixes).

ALSA: ua101: fix division by zero at probe (git-fixes).

ALSA: uapi: Fix a C++ style comment in asound.h (git-fixes).

ALSA: usb-audio: Add Audient iD14 to mixer map quirk table (git-fixes).

ALSA: usb-audio: Add minimal-mute notion in dB mapping table
 (bsc#1192375).

ALSA: usb-audio: Add Schiit Hel device to mixer map quirk table
 (git-fixes).

ALSA: usb-audio: Fix dB level of Bose Revolve+ SoundLink (bsc#1192375).

ALSA: usb-audio: Use int for dB map values (bsc#1192375).

ARM: socfpga: Fix crash with CONFIG_FORTIRY_SOURCE (bsc#1192473).

ASoC: cs42l42: Correct some register default values (git-fixes).

ASoC: cs42l42: Defer probe if request_threaded_irq() returns
 EPROBE_DEFER (git-fixes).

ASoC: cs42l42: Do not set defaults for volatile ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.31.1", rls:"SLES15.0SP3"))) {
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

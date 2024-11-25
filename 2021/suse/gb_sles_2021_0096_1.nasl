# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0096.1");
  script_cve_id("CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-11668", "CVE-2020-27068", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-29370", "CVE-2020-29373", "CVE-2020-29660", "CVE-2020-29661");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 02:12:54 +0000 (Thu, 09 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0096-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210096-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-0444: Fixed a bad kfree due to a logic error in
 audit_data_to_entry (bnc#1180027).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180029).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
 do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).

CVE-2020-11668: Fixed the mishandling of invalid descriptors in the
 Xirlink camera USB driver (bnc#1168952).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
 check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation
 (bnc#1179601).

CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls
 (bsc#1179960).

CVE-2020-27830: Fixed a null pointer dereference in speakup
 (bsc#1179656).

CVE-2020-29370: Fixed a race condition in kmem_cache_alloc_bulk
 (bnc#1179435).

CVE-2020-29373: Fixed an unsafe handling of the root directory during
 path lookups in fs/io_uring.c (bnc#1179434).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179745).

The following non-security bugs were fixed:

ACPI: APEI: Kick the memory_failure() queue for synchronous errors
 (jsc#SLE-16610).

ACPI: PNP: compare the string length in the matching_id() (git-fixes).

ALSA/hda: apply jack fixup for the Acer Veriton N4640G/N6640G/N2510G
 (git-fixes).

ALSA: core: memalloc: add page alignment for iram (git-fixes).

ALSA: hda/ca0132 - Change Input Source enum strings (git-fixes).

ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg (git-fixes).

ALSA: hda/generic: Add option to enforce preferred_dacs pairs
 (git-fixes).

ALSA: hda/hdmi: always print pin NIDs as hexadecimal (git-fixes).

ALSA: hda/hdmi: packet buffer index must be set before reading value
 (git-fixes).

ALSA: hda/proc - print DP-MST connections (git-fixes).

ALSA: hda/realtek - Add new codec supported for ALC897 (git-fixes).

ALSA: hda/realtek - Add supported for more Lenovo ALC285 Headset Button
 (git-fixes).

ALSA: hda/realtek - Enable headset mic of ASUS Q524UQK with ALC255
 (git-fixes).

ALSA: hda/realtek - Enable headset mic of ASUS X430UN with ALC256
 (git-fixes).

ALSA: hda/realtek - Fixed Dell AIO wrong sound tone (git-fixes).

ALSA: hda/realtek: Add mute LED quirk to yet another HP x360 model
 (git-fixes).

ALSA: hda/realtek: Add quirk for MSI-GP73 (git-fixes).

ALSA: hda/realtek: Apply jack fixup for Quanta NL3 (git-fixes).

ALSA: hda/realtek: Enable headset of ASUS UX482EG & B9400CEA with ALC294
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.32.1", rls:"SLES15.0SP2"))) {
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

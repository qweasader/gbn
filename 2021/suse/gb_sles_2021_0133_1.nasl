# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0133.1");
  script_cve_id("CVE-2018-20669", "CVE-2019-20934", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-28374", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-02-10T10:32:19+0000");
  script_tag(name:"last_modification", value:"2023-02-10 10:32:19 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 02:12:00 +0000 (Thu, 09 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0133-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210133-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-28374: Fixed a LIO security issue (bsc#1178372).

CVE-2020-36158: Fixed a potential remote code execution in the Marvell
 mwifiex driver (bsc#1180559).

CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls
 (bsc#1179960).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
 do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
 check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180029).

CVE-2020-0444: Fixed a bad kfree due to a logic error in
 audit_data_to_entry (bnc#1180027).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179745).

CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction
 Services (RTAS) interface, affecting guests running on top of PowerVM or
 KVM hypervisors (bnc#1179107).

CVE-2019-20934: Fixed a use-after-free in show_numa_stats() because NUMA
 fault statistics were inappropriately freed, aka CID-16d51a590a8c
 (bsc#1179663).

CVE-2020-27786: Fixed a use after free in kernel midi subsystem
 snd_rawmidi_kernel_read1() (bsc#1179601).

CVE-2020-4788: Fixed an issue with IBM Power9 processors could have
 allowed a local user to obtain sensitive information from the data in
 the L1 cache under extenuating circumstances (bsc#1177666).

CVE-2018-20669: Fixed an improper check i915_gem_execbuffer2_ioctl in
 drivers/gpu/drm/i915/i915_gem_execbuffer.c (bsc#1122971).

The following non-security bugs were fixed:

ACPI: PNP: compare the string length in the matching_id() (git-fixes).

ACPICA: Disassembler: create buffer fields in ACPI_PARSE_LOAD_PASS1
 (git-fixes).

ACPICA: Do not increment operation_region reference counts for field
 units (git-fixes).

ALSA: ca0106: fix error code handling (git-fixes).

ALSA: ctl: allow TLV read operation for callback type of element in
 locked case (git-fixes).

ALSA: hda - Fix silent audio output and corrupted input on MSI X570-A
 PRO (git-fixes).

ALSA: hda/ca0132 - Change Input Source enum strings (git-fixes).

ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg (git-fixes).

ALSA: hda/generic: Add option to enforce preferred_dacs pairs
 (git-fixes).

ALSA: hda/hdmi: always check pin power status in i915 pin fixup
 (git-fixes).

ALSA: hda/realtek - Add new codec supported for ALC897 (git-fixes).

ALSA: hda/realtek - Couldn't detect Mic if booting with headset plugged
 (git-fixes).

ALSA: hda/realtek ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.57.1", rls:"SLES12.0SP5"))) {
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
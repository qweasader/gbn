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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1699.1");
  script_cve_id("CVE-2019-20810", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-13974");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 23:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1699-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201699-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-10768: The prctl() function could be used to enable indirect
 branch speculation even after it has been disabled. (bnc#1172783)

CVE-2020-10766: A bug in the logic handling could allow an attacker with
 a local account to disable SSBD protection. (bnc#1172781)

CVE-2020-10767: A IBPB would be disabled when STIBP was not available or
 when Enhanced Indirect Branch Restricted Speculation (IBRS) was
 available. This is unexpected behaviour could leave the system open to a
 spectre v2 style attack (bnc#1172782)

CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer overflow if
 k_ascii was called several times in a row (bnc#1172775)

CVE-2019-20810: go7007_snd_init did not call snd_card_free for a failure
 path, which caused a memory leak (bnc#1172458)

The following non-security bugs were fixed:

ACPI: PM: Avoid using power resources if there are none for D0
 (bsc#1051510).

ALSA: es1688: Add the missed snd_card_free() (bsc#1051510).

ALSA: hda/hdmi - enable runtime pm for newer AMD display audio
 (bsc#1111666).

ALSA: hda/realtek - Add LED class support for micmute LED (bsc#1111666).

ALSA: hda/realtek - Enable micmute LED on and HP system (bsc#1111666).

ALSA: hda/realtek - Fix unused variable warning w/o
 CONFIG_LEDS_TRIGGER_AUDIO (bsc#1111666).

ALSA: hda/realtek - Introduce polarity for micmute LED GPIO
 (bsc#1111666).

ALSA: hda/realtek - add a pintbl quirk for several Lenovo machines
 (bsc#1111666).

ALSA: hda: Add ElkhartLake HDMI codec vid (bsc#1111666).

ALSA: hda: add sienna_cichlid audio asic id for sienna_cichlid up
 (bsc#1111666).

ALSA: pcm: disallow linking stream to itself (bsc#1111666).

ALSA: usb-audio: Add Pioneer DJ DJM-900NXS2 support (bsc#1111666).

ALSA: usb-audio: Add duplex sound support for USB devices using implicit
 feedback (bsc#1111666).

ALSA: usb-audio: Add vendor, product and profile name for HP Thunderbolt
 Dock (bsc#1111666).

ALSA: usb-audio: Clean up quirk entries with macros (bsc#1111666).

ALSA: usb-audio: Fix inconsistent card PM state after resume
 (bsc#1111666).

ALSA: usb-audio: Fix racy list management in output queue (bsc#1111666).

ALSA: usb-audio: Manage auto-pm of all bundled interfaces (bsc#1111666).

ALSA: usb-audio: Use the new macro for HP Dock rename quirks
 (bsc#1111666).

CDC-ACM: heed quirk also in error handling (git-fixes).

HID: sony: Fix for broken buttons on DS3 USB dongles (bsc#1051510).

KVM: x86/mmu: Set mmio_value to '0' if reserved #PF can't be generated
 (bsc#1171904).

KVM: x86: only do L1TF workaround on affected processors (bsc#1171904).

NFS: Fix an RCU lock leak in nfs4_refresh_delegation_stateid()
 (bsc#1170592).

NFSv4: Retry CLOSE and DELEGRETURN on NFS4ERR_OLD_STATEID (bsc#1170592).

PCI/PM: Call .bridge_d3() hook only if non-NULL ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.19.1", rls:"SLES12.0SP5"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2645.1");
  script_cve_id("CVE-2021-21781", "CVE-2021-22543", "CVE-2021-35039", "CVE-2021-3609", "CVE-2021-3612", "CVE-2021-3659", "CVE-2021-37576");
  script_tag(name:"creation_date", value:"2021-08-11 02:25:15 +0000 (Wed, 11 Aug 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-05 18:09:00 +0000 (Thu, 05 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2645-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212645-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3659: Fixed a NULL pointer dereference in llsec_key_alloc() in
 net/mac802154/llsec.c (bsc#1188876).

CVE-2021-21781: Fixed a information disclosure vulnerability in the ARM
 SIGPAGE (bsc#1188445).

CVE-2021-22543: Fixed improper handling of VM_IO<pipe>VM_PFNMAP vmas in KVM,
 which could bypass RO checks and can lead to pages being freed while
 still accessible by the VMM and guest. This allowed users with the
 ability to start and control a VM to read/write random pages of memory
 and can result in local privilege escalation (bsc#1186482).

CVE-2021-37576: Fixed an issue on the powerpc platform, where a KVM
 guest OS user could cause host OS memory corruption via rtas_args.nargs
 (bsc#1188838).

CVE-2021-3609: Fixed a potential local privilege escalation in the CAN
 BCM networking protocol (bsc#1187215).

CVE-2021-3612: Fixed an out-of-bounds memory write flaw in the joystick
 devices subsystem. This flaw allowed a local user to crash the system or
 possibly escalate their privileges on the system. (bsc#1187585)

CVE-2021-35039: Fixed mishandling of signature verification. Without
 CONFIG_MODULE_SIG, verification that a kernel module is signed, for
 loading via init_module, did not occur for a module.sig_enforce=1
 command-line argument (bsc#1188080).

The following non-security bugs were fixed:

ACPI: AMBA: Fix resource name in /proc/iomem (git-fixes).

ACPI: APEI: fix synchronous external aborts in user-mode (git-fixes).

ACPI: DPTF: Fix reading of attributes (git-fixes).

ACPI: EC: Make more Asus laptops use ECDT _GPE (git-fixes).

ACPI: PM / fan: Put fan device IDs into separate header file (git-fixes).

ACPI: bus: Call kobject_put() in acpi_init() error path (git-fixes).

ACPI: processor idle: Fix up C-state latency if not ordered (git-fixes).

ACPI: property: Constify stubs for CONFIG_ACPI=n case (git-fixes).

ACPI: resources: Add checks for ACPI IRQ override (git-fixes).

ACPI: sysfs: Fix a buffer overrun problem with description_show()
 (git-fixes).

ACPI: video: Add quirk for the Dell Vostro 3350 (git-fixes).

ACPICA: Fix memory leak caused by _CID repair function (git-fixes).

ALSA: ac97: fix PM reference leak in ac97_bus_remove() (git-fixes).

ALSA: bebob: add support for ToneWeal FW66 (git-fixes).

ALSA: firewire-motu: fix detection for S/PDIF source on optical
 interface in v2 protocol (git-fixes).

ALSA: firewire-motu: fix stream format for MOTU 8pre FireWire
 (git-fixes).

ALSA: hda/realtek: Add another ALC236 variant support (git-fixes).

ALSA: hda/realtek: Apply LED fixup for HP Dragonfly G1, too (git-fixes).

ALSA: hda/realtek: Fix bass speaker DAC mapping for Asus UM431D
 (git-fixes).

ALSA: hda/realtek: Fix pop noise and 2 Front Mic issues on a machine
 (git-fixes).

ALSA: hda/realtek: Improve fixup ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.17.1", rls:"SLES15.0SP3"))) {
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

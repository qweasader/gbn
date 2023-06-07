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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2574.1");
  script_cve_id("CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14386", "CVE-2020-16166", "CVE-2020-1749", "CVE-2020-24394");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2574-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202574-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-1749: Use ip6_dst_lookup_flow instead of ip6_dst_lookup
 (bsc#1165629).

CVE-2020-14314: Fixed a potential negative array index in do_split()
 (bsc#1173798).

CVE-2020-14356: Fixed a null pointer dereference in cgroupv2 subsystem
 which could have led to privilege escalation (bsc#1175213).

CVE-2020-14331: Fixed a missing check in vgacon scrollback handling
 (bsc#1174205).

CVE-2020-16166: Fixed a potential issue which could have allowed remote
 attackers to make observations that help to obtain sensitive information
 about the internal state of the network RNG (bsc#1174757).

CVE-2020-24394: Fixed an issue which could set incorrect permissions on
 new filesystem objects when the filesystem lacks ACL support
 (bsc#1175518).

CVE-2020-14386: Fixed a potential local privilege escalation via memory
 corruption (bsc#1176069).

The following non-security bugs were fixed:

ACPI: kABI fixes for subsys exports (bsc#1174968).

ACPI / LPSS: Resume BYT/CHT I2C controllers from resume_noirq
 (bsc#1174968).

ACPI / LPSS: Use acpi_lpss_* instead of acpi_subsys_* functions for
 hibernate (bsc#1174968).

ACPI: PM: Introduce 'poweroff' callbacks for ACPI PM domain and LPSS
 (bsc#1174968).

ACPI: PM: Simplify and fix PM domain hibernation callbacks (bsc#1174968).

ALSA: core: pcm_iec958: fix kernel-doc (bsc#1111666).

ALSA: echoaduio: Drop superfluous volatile modifier (bsc#1111666).

ALSA: echoaudio: Fix potential Oops in snd_echo_resume() (bsc#1111666).

ALSA: hda: Add support for Loongson 7A1000 controller (bsc#1111666).

ALSA: hda/ca0132 - Add new quirk ID for Recon3D (bsc#1111666).

ALSA: hda/ca0132 - Fix AE-5 microphone selection commands (bsc#1111666).

ALSA: hda/ca0132 - Fix ZxR Headphone gain control get value
 (bsc#1111666).

ALSA: hda: fix NULL pointer dereference during suspend (git-fixes).

ALSA: hda: fix snd_hda_codec_cleanup() documentation (bsc#1111666).

ALSA: hda - fix the micmute led status for Lenovo ThinkCentre AIO
 (bsc#1111666).

ALSA: hda/realtek: Add alc269/alc662 pin-tables for Loongson-3 laptops
 (bsc#1111666).

ALSA: hda/realtek: Add model alc298-samsung-headphone (git-fixes).

ALSA: hda/realtek: Add mute LED and micmute LED support for HP systems
 (bsc#1111666).

ALSA: hda/realtek - Add quirk for Lenovo Carbon X1 8th gen (bsc#1111666).

ALSA: hda/realtek - Add quirk for MSI GE63 laptop (bsc#1111666).

ALSA: hda/realtek - Add quirk for MSI GL63 (bsc#1111666).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion (git-fixes).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex Book (git-fixes).

ALSA: hda/realtek - change to suitable link model for ASUS platform
 (bsc#1111666).

ALSA: hda/realtek - Check headset type by unplug and resume
 (bsc#1111666).

ALSA: hda/realtek - Enable audio jacks of Acer vCopperbox ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
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

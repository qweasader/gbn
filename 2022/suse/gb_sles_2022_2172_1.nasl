# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2172.1");
  script_cve_id("CVE-2020-26541", "CVE-2022-1012", "CVE-2022-1966", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-20141", "CVE-2022-32250");
  script_tag(name:"creation_date", value:"2022-06-27 04:38:24 +0000 (Mon, 27 Jun 2022)");
  script_version("2022-10-03T10:13:16+0000");
  script_tag(name:"last_modification", value:"2022-10-03 10:13:16 +0000 (Mon, 03 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:00 +0000 (Fri, 30 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2172-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222172-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated.

The following security bugs were fixed:

CVE-2022-1012: Fixed a small table perturb size in the TCP source port
 generation algorithm which could leads to information leak.
 (bsc#1199482).

CVE-2022-20141: Fixed an use after free due to improper locking. This
 bug could lead to local escalation of privilege when opening and closing
 inet sockets with no additional execution privileges needed.
 (bnc#1200604)

CVE-2022-32250: Fixed an use-after-free bug in the netfilter subsystem.
 This flaw allowed a local attacker with user access to cause a privilege
 escalation issue. (bnc#1200015)

CVE-2022-1975: Fixed a sleep-in-atomic bug that allows attacker to crash
 linux kernel by simulating nfc device from user-space. (bsc#1200143)

CVE-2022-1974: Fixed an use-after-free that could causes kernel crash by
 simulating an nfc device from user-space. (bsc#1200144)

CVE-2020-26541: Enforce the secure boot forbidden signature database
 (aka dbx) protection mechanism. (bnc#1177282)

The following non-security bugs were fixed:

ACPI: PM: Block ASUS B1400CEAE from suspend to idle by default
 (git-fixes).

ACPI: sysfs: Fix BERT error region memory mapping (git-fixes).

ACPI: sysfs: Make sparse happy about address space in use (git-fixes).

ALSA: hda/conexant - Fix loopback issue with CX20632 (git-fixes).

ALSA: usb-audio: Optimize TEAC clock quirk (git-fixes).

ALSA: usb-audio: Set up (implicit) sync for Saffire 6 (git-fixes).

ALSA: usb-audio: Skip generic sync EP parse for secondary EP (git-fixes).

ALSA: usb-audio: Workaround for clock setup on TEAC devices (git-fixes).

arm64: dts: rockchip: Move drive-impedance-ohm to emmc phy on rk3399
 (git-fixes)

ASoC: dapm: Do not fold register value changes into notifications
 (git-fixes).

ASoC: max98357a: remove dependency on GPIOLIB (git-fixes).

ASoC: rt5645: Fix errorenous cleanup order (git-fixes).

ASoC: tscs454: Add endianness flag in snd_soc_component_driver
 (git-fixes).

ata: libata-transport: fix {dma<pipe>pio<pipe>xfer}_mode sysfs files (git-fixes).

ath9k: fix QCA9561 PA bias level (git-fixes).

b43: Fix assigning negative value to unsigned variable (git-fixes).

b43legacy: Fix assigning negative value to unsigned variable (git-fixes).

blk-mq: fix tag_get wait task can't be awakened (bsc#1200263).

blk-mq: Fix wrong wakeup batch configuration which will cause hang
 (bsc#1200263).

block: fix bio_clone_blkg_association() to associate with proper
 blkcg_gq (bsc#1200259).

btrfs: tree-checker: fix incorrect printk format (bsc#1200249).

certs/blacklist_hashes.c: fix const confusion in certs blacklist
 (git-fixes).

cfg80211: set custom regdomain after wiphy registration (git-fixes).

clocksource/drivers/oxnas-rps: Fix irq_of_parse_and_map() return value
 (git-fixes).

clocksource/drivers/sp804: Avoid error on multiple instances (git-fixes).

dma-buf: fix use of ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.62.1", rls:"SLES15.0SP3"))) {
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

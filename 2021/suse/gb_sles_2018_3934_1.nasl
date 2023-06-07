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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3934.1");
  script_cve_id("CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-01-19T10:10:48+0000");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:34:00 +0000 (Tue, 17 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3934-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183934-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel for Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in
 drivers/cdrom/cdrom.c could be used by local attackers to read kernel
 memory because a cast from unsigned long to int interferes with bounds
 checking. This is similar to CVE-2018-10940 and CVE-2018-16658
 (bnc#1113751).

CVE-2018-18445: Faulty computation of numeric bounds in the BPF verifier
 permits out-of-bounds memory accesses because adjust_scalar_min_max_vals
 in kernel/bpf/verifier.c mishandled 32-bit right shifts (bnc#1112372).

CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are
 able to access pseudo terminals) to hang/block further usage of any
 pseudo terminal devices due to an EXTPROC versus ICANON confusion in
 TIOCINQ (bnc#1094825).

CVE-2017-18224: fs/ocfs2/aops.c omits use of a semaphore and
 consequently has a race condition for access to the extent tree during
 read operations in DIRECT mode, which allowed local users to cause a
 denial of service (BUG) by modifying a certain e_cpos field
 (bnc#1084831).

CVE-2017-16533: The usbhid_parse function in
 drivers/hid/usbhid/hid-core.c allowed local users to cause a denial of
 service (out-of-bounds read and system crash) or possibly have
 unspecified other impact via a crafted USB device (bnc#1066674).

The following non-security bugs were fixed:
acpi, nfit: Prefer _DSM over _LSR for namespace label reads (bsc#112128).

acpi / processor: Fix the return value of acpi_processor_ids_walk()
 (bsc#1051510).

aio: fix io_destroy(2) vs. lookup_ioctx() race (git-fixes).

alsa: hda: Add 2 more models to the power_save blacklist (bsc#1051510).

alsa: hda - Add mic quirk for the Lenovo G50-30 (17aa:3905)
 (bsc#1051510).

alsa: hda - Add quirk for ASUS G751 laptop (bsc#1051510).

alsa: hda - Fix headphone pin config for ASUS G751 (bsc#1051510).

alsa: hda: fix unused variable warning (bsc#1051510).

alsa: hda/realtek - Cannot adjust speaker's volume on Dell XPS 27 7760
 (bsc#1051510).

alsa: hda/realtek - Fix the problem of the front MIC on the Lenovo M715
 (bsc#1051510).

alsa: usb-audio: update quirk for B&W PX to remove microphone
 (bsc#1051510).

apparmor: Check buffer bounds when mapping permissions mask (git-fixes).

ARM: bcm2835: Add GET_THROTTLED firmware property (bsc#1108468).

ASoC: intel: skylake: Add missing break in skl_tplg_get_token()
 (bsc#1051510).

ASoC: Intel: Skylake: Reset the controller in probe (bsc#1051510).

ASoC: rsnd: adg: care clock-frequency size (bsc#1051510).

ASoC: rsnd: do not fallback to PIO mode when -EPROBE_DEFER (bsc#1051510).

ASoC: rt5514: Fix the issue of the delay volume applied again
 (bsc#1051510).

ASoC: sigmadsp: safeload should not have lower byte limit (bsc#1051510).

ASoC: wm8804: Add ACPI support (bsc#1051510).

ath10k: fix kernel panic issue ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
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

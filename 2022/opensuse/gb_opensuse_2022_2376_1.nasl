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
  script_oid("1.3.6.1.4.1.25623.1.0.854812");
  script_version("2022-07-25T10:11:13+0000");
  script_cve_id("CVE-2021-26341", "CVE-2021-4157", "CVE-2022-1679", "CVE-2022-20132", "CVE-2022-20154", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-33981", "CVE-2022-34918");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-25 10:11:13 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 15:31:00 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 01:01:41 +0000 (Wed, 13 Jul 2022)");
  script_name("openSUSE: Security Advisory for the (SUSE-SU-2022:2376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2376-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5Q5WIEGX7YHOWE74L3GWRHQJSRWY7ZER");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the SUSE-SU-2022:2376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive
     various security and bugfixes.
  The following security bugs were fixed:

  - CVE-2022-29900, CVE-2022-29901: Fixed the RETBLEED attack, a new Spectre
       like Branch Target Buffer attack, that can leak arbitrary kernel
       information (bsc#1199657).

  - CVE-2022-34918: Fixed a buffer overflow with nft_set_elem_init() that
       could be used by a local attacker to escalate privileges (bnc#1201171).

  - CVE-2021-26341: Some AMD CPUs may transiently execute beyond
       unconditional direct branches, which may potentially result in data
       leakage (bsc#1201050).

  - CVE-2022-1679: Fixed a use-after-free in the Atheros wireless driver in
       the way a user forces the ath9k_htc_wait_for_target function to fail
       with some input messages (bsc#1199487).

  - CVE-2022-20132: Fixed out of bounds read due to improper input
       validation in lg_probe and related functions of hid-lg.c (bsc#1200619).

  - CVE-2022-33981: Fixed use-after-free in floppy driver (bsc#1200692)

  - CVE-2021-4157: Fixed an out of memory bounds write flaw in the NFS
       subsystem, related to the replication of files with NFS. A user could
       potentially crash the system or escalate privileges on the system
       (bsc#1194013).

  - CVE-2022-20154: Fixed a use after free due to a race condition in
       lock_sock_nested of sock.c. This could lead to local escalation of
       privilege with System execution privileges needed (bsc#1200599).
  The following non-security bugs were fixed:

  - ALSA: hda/conexant: Fix missing beep setup (git-fixes).

  - ALSA: hda/realtek - Add HW8326 support (git-fixes).

  - ALSA: hda/realtek: Add quirk for Clevo PD70PNT (git-fixes).

  - ALSA: hda/realtek - ALC897 headset MIC no sound (git-fixes).

  - ALSA: hda/via: Fix missing beep setup (git-fixes).

  - arm64: ftrace: fix branch range checks (git-fixes)

  - ASoC: cs35l36: Update digital volume TLV (git-fixes).

  - ASoC: cs42l52: Correct TLV for Bypass Volume (git-fixes).

  - ASoC: cs42l52: Fix TLV scales for mixer controls (git-fixes).

  - ASoC: cs42l56: Correct typo in minimum level for SX volume controls
       (git-fixes).

  - ASoC: cs53l30: Correct number of volume levels on SX controls
       (git-fixes).

  - ASoC: es8328: Fix event generation for deemphasis control (git-fixes).

  - ASoC: nau8822: Add operation for internal PLL off and on (git-fixes).

  - ASoC: wm8962: Fix suspend while playing music (git-fixes).

  - ASoC: wm_adsp: Fix event generation for wm_adsp_fw_put() ( ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure-debuginfo", rpm:"cluster-md-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure-debuginfo", rpm:"dlm-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure-debuginfo", rpm:"gfs2-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra-debuginfo", rpm:"kernel-azure-extra-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-livepatch-devel", rpm:"kernel-azure-livepatch-devel~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional-debuginfo", rpm:"kernel-azure-optional-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure-debuginfo", rpm:"kselftests-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure-debuginfo", rpm:"ocfs2-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure-debuginfo", rpm:"reiserfs-kmp-azure-debuginfo~5.3.18~150300.38.69.1", rls:"openSUSELeap15.3"))) {
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
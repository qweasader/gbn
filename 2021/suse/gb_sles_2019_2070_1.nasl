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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2070.1");
  script_cve_id("CVE-2018-20855", "CVE-2019-1125", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 19:46:00 +0000 (Fri, 02 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2070-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192070-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-20855: An issue was discovered in the Linux kernel In
 create_qp_common in drivers/infiniband/hw/mlx5/qp.c,
 mlx5_ib_create_qp_resp was never initialized, resulting in a leak of
 stack memory to userspace(bsc#1143045).

CVE-2019-1125: Exclude ATOMs from speculation through SWAPGS
 (bsc#1139358).

CVE-2019-14283: In the Linux kernel, set_geometry in
 drivers/block/floppy.c did not validate the sect and head fields, as
 demonstrated by an integer overflow and out-of-bounds read. It could be
 triggered by an unprivileged local user when a floppy disk was inserted.
 NOTE: QEMU creates the floppy device by default. (bnc#1143191)

CVE-2019-11810: An issue was discovered in the Linux kernel A NULL
 pointer dereference could occur when megasas_create_frame_pool() failed
 in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c.
 This caused a Denial of Service, related to a use-after-free
 (bnc#1134399).

CVE-2019-13648: In the Linux kernel on the powerpc platform, when
 hardware transactional memory was disabled, a local user could cause a
 denial of service (TM Bad Thing exception and system crash) via a
 sigreturn() system call that sent a crafted signal frame. (bnc#1142254)

CVE-2019-13631: In parse_hid_report_descriptor in
 drivers/input/tablet/gtco.c in the Linux kernel, a malicious USB device
 could send an HID report that triggered an out-of-bounds write during
 generation of debugging messages. (bnc#1142023)

The following non-security bugs were fixed:
 Correct the CVE and bug reference for a floppy security fix
 (CVE-2019-14284,bsc#1143189) A dedicated CVE was already assigned

acpi/nfit: Always dump _DSM output payload (bsc#1142351).

Add back sibling paca poiter to paca (bsc#1055117).

Add support for crct10dif-vpmsum ().

af_unix: remove redundant lockdep class (git-fixes).

alsa: compress: Be more restrictive about when a drain is allowed
 (bsc#1051510).

alsa: compress: Do not allow partial drain operations on capture
 streams (bsc#1051510).

alsa: compress: Fix regression on compressed capture streams
 (bsc#1051510).

alsa: compress: Prevent bypasses of set_params (bsc#1051510).

alsa: hda - Add a conexant codec entry to let mute led work
 (bsc#1051510).

alsa: hda - Do not resume forcibly i915 HDMI/DP codec (bsc#1111666).

alsa: hda - Fix intermittent CORB/RIRB stall on Intel chips
 (bsc#1111666).

alsa: hda/hdmi - Fix i915 reverse port/pin mapping (bsc#1111666).

alsa: hda/hdmi - Remove duplicated define (bsc#1111666).

alsa: hda - Optimize resume for codecs without jack detection
 (bsc#1111666).

alsa: hda/realtek: apply ALC891 headset fixup to one Dell machine
 (bsc#1051510).

alsa: hda/realtek - Fixed Headphone Mic can't record on Dell platform
 (bsc#1051510).

alsa: hda/realtek - Headphone Mic can't ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
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

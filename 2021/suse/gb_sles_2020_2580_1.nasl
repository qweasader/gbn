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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2580.1");
  script_cve_id("CVE-2020-14386");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2580-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2580-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202580-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2580-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.

The following security bug was fixed:

CVE-2020-14386: Fixed a potential local privilege escalation via memory
 corruption (bsc#1176069).

The following non-security bugs were fixed:

bcache: allocate meta data pages as compound pages (bsc#1172873).

block: check queue's limits.discard_granularity in
 __blkdev_issue_discard() (bsc#1152148).

block: improve discard bio alignment in __blkdev_issue_discard()
 (bsc#1152148).

char: virtio: Select VIRTIO from VIRTIO_CONSOLE (bsc#1175667).

dax: do not print error message for non-persistent memory block device
 (bsc#1171073).

dax: print error message by pr_info() in __generic_fsdax_supported()
 (bsc#1171073).

device property: Fix the secondary firmware node handling in
 set_primary_fwnode() (git-fixes).

dpaa_eth: Fix one possible memleak in dpaa_eth_probe (bsc#1175996).

drm/amd/powerplay: Fix hardmins not being sent to SMU for RV (git-fixes).

drm/msm/a6xx: fix crashdec section name typo (git-fixes).

drm/msm/adreno: fix updating ring fence (git-fixes).

drm/msm/gpu: make ringbuffer readonly (git-fixes).

drm/xen-front: Fix misused IS_ERR_OR_NULL checks (bsc#1065600).

efi: Add support for EFI_RT_PROPERTIES table (bsc#1174029, bsc#1174110,
 bsc#1174111).

efi: avoid error message when booting under Xen (bsc#1172419).

efi/efivars: Expose RT service availability via efivars abstraction
 (bsc#1174029, bsc#1174110, bsc#1174111).

efi: libstub/tpm: enable tpm eventlog function for ARM platforms
 (bsc#1173267).

efi: Mark all EFI runtime services as unsupported on non-EFI boot
 (bsc#1174029, bsc#1174110, bsc#1174111).

efi: Register EFI rtc platform device only when available (bsc#1174029,
 bsc#1174110, bsc#1174111).

efi: Store mask of supported runtime services in struct efi
 (bsc#1174029, bsc#1174110, bsc#1174111).

efi: Use EFI ResetSystem only when available (bsc#1174029, bsc#1174110,
 bsc#1174111).

efi: Use more granular check for availability for variable services
 (bsc#1174029, bsc#1174110, bsc#1174111).

ext4: handle read only external journal device (bsc#1176063).

felix: Fix initialization of ioremap resources (bsc#1175997).

Fix build error when CONFIG_ACPI is not set/enabled: (bsc#1065600).

infiniband: hfi1: Use EFI GetVariable only when available (bsc#1174029,
 bsc#1174110, bsc#1174111).

integrity: Check properly whether EFI GetVariable() is available
 (bsc#1174029, bsc#1174110, bsc#1174111).

kabi: Fix kABI after EFI_RT_PROPERTIES table backport (bsc#1174029,
 bsc#1174110, bsc#1174111).

kabi/severities: ignore kABI for net/ethernet/mscc/ References:
 bsc#1176001,bsc#1175999 Exported symbols from drivers/net/ethernet/mscc/
 are only used by drivers/net/dsa/ocelot/

mei: fix CNL itouch device number to match the spec (bsc#1175952).

mei: me: disable mei interface on LBG servers (bsc#1175952).

mei: me: disable ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.18.1", rls:"SLES15.0SP2"))) {
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

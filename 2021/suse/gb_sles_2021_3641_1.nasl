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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3641.1");
  script_cve_id("CVE-2018-13405", "CVE-2021-33033", "CVE-2021-34866", "CVE-2021-3542", "CVE-2021-3655", "CVE-2021-3715", "CVE-2021-3760", "CVE-2021-3772", "CVE-2021-3896", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42252", "CVE-2021-42739", "CVE-2021-43056");
  script_tag(name:"creation_date", value:"2021-11-10 07:32:27 +0000 (Wed, 10 Nov 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 17:39:00 +0000 (Fri, 25 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3641-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3641-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213641-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3641-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3772: Fixed sctp vtag check in sctp_sf_ootb (bsc#1190351).

CVE-2021-3655: Fixed a missing size validations on inbound SCTP packets,
 which may have allowed the kernel to read uninitialized memory
 (bsc#1188563).

CVE-2021-43056: Fixed possible KVM host crash via malicious KVM guest on
 Power8 (bnc#1192107).

CVE-2021-3896: Fixed a array-index-out-bounds in detach_capi_ctr in
 drivers/isdn/capi/kcapi.c (bsc#1191958).

CVE-2021-3760: Fixed a use-after-free vulnerability with the
 ndev->rf_conn_info object (bsc#1190067).

CVE-2021-42739: The firewire subsystem had a buffer overflow related to
 drivers/media/firewire/firedtv-avc.c and
 drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled
 bounds checking (bsc#1184673).

CVE-2021-3542: Fixed heap buffer overflow in firedtv driver
 (bsc#1186063).

CVE-2021-33033: Fixed a use-after-free in cipso_v4_genopt in
 net/ipv4/cipso_ipv4.c because the CIPSO and CALIPSO refcounting for the
 DOI definitions is mishandled (bsc#1186109).

CVE-2021-3715: Fixed a use-after-free in route4_change() in
 net/sched/cls_route.c (bsc#1190349).

CVE-2021-34866: Fixed eBPF Type Confusion Privilege Escalation
 Vulnerability (bsc#1191645).

CVE-2021-42252: Fixed an issue inside aspeed_lpc_ctrl_mmap that could
 have allowed local attackers to access the Aspeed LPC control interface
 to overwrite memory in the kernel and potentially execute privileges
 (bnc#1190479).

CVE-2021-41864: Fixed prealloc_elems_and_freelist that allowed
 unprivileged users to trigger an eBPF multiplication integer overflow
 with a resultant out-of-bounds write (bnc#1191317).

CVE-2021-42008: Fixed a slab out-of-bounds write in the decode_data
 function in drivers/net/hamradio/6pack.c. Input from a process that had
 the CAP_NET_ADMIN capability could have lead to root access
 (bsc#1191315).

The following non-security bugs were fixed:

ACPI: NFIT: Use fallback node id when numa info in NFIT table is
 incorrect (git-fixes).

ACPI: bgrt: Fix CFI violation (git-fixes).

ACPI: fix NULL pointer dereference (git-fixes).

ACPI: fix NULL pointer dereference (git-fixes).

ALSA: hda - Enable headphone mic on Dell Latitude laptops with ALC3254
 (git-fixes).

ALSA: hda/realtek - ALC236 headset MIC recording issue (git-fixes).

ALSA: hda/realtek: Add quirk for Clevo PC50HS (git-fixes).

ALSA: hda/realtek: Add quirk for Clevo X170KM-G (git-fixes).

ALSA: hda/realtek: Add quirk for TongFang PHxTxX1 (git-fixes).

ALSA: hda/realtek: Complete partial device name to avoid ambiguity
 (git-fixes).

ALSA: hda/realtek: Enable 4-speaker output for Dell Precision 5560
 laptop (git-fixes).

ALSA: hda/realtek: Fix for quirk to enable speaker output on the Lenovo
 13s Gen2 (git-fixes).

ALSA: hda/realtek: Fix the mic type detection issue for ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.28.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.28.1", rls:"SLES15.0SP3"))) {
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

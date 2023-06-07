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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2658.1");
  script_cve_id("CVE-2017-18551", "CVE-2017-18595", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-10207", "CVE-2019-11477", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15099", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15291", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-04-21T10:20:09+0000");
  script_tag(name:"last_modification", value:"2023-04-21 10:20:09 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 14:08:00 +0000 (Wed, 19 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2658-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2658-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192658-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2658-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2017-18551: An issue was discovered in drivers/i2c/i2c-core-smbus.c.
 There was an out of bounds write in the function i2c_smbus_xfer_emulated
 (bnc#1146163).

CVE-2017-18595: A double free may be caused by the function
 allocate_trace_buffer in the file kernel/trace/trace.c (bnc#1149555).

CVE-2018-20976: An issue was discovered in fs/xfs/xfs_super.c. A use
 after free exists, related to xfs_fs_fill_super failure (bnc#1146285).

CVE-2018-21008: A use-after-free could have been caused by the function
 rsi_mac80211_detach in the file
 drivers/net/wireless/rsi/rsi_91x_mac80211.c (bnc#1149591).

CVE-2019-10207: A local denial of service using
 HCIUARTSETPROTO/HCI_UART_MRVL was fixed (bnc#1123959 bnc#1142857).

CVE-2019-11477: Jonathan Looney discovered that the
 TCP_SKB_CB(skb)->tcp_gso_segs value was subject to an integer overflow
 in the Linux kernel when handling TCP Selective Acknowledgments (SACKs).
 A remote attacker could use this to cause a denial of service.
 (bnc#1132686 bnc#1137586).

CVE-2019-14814: There was a heap-based buffer overflow in the Marvell
 wifi chip driver, that allowed local users to cause a denial of service
 (system crash) or possibly execute arbitrary code (bnc#1146512).

CVE-2019-14814: There was a heap-based buffer overflow in the Marvell
 wifi chip driver, that allowed local users to cause a denial of service
 (system crash) or possibly execute arbitrary code (bnc#1146512).

CVE-2019-14816: There was a heap-based buffer overflow in the Marvell
 wifi chip driver, that allowed local users to cause a denial of service
 (system crash) or possibly execute arbitrary code (bnc#1146516).

CVE-2019-14821: An out-of-bounds access issue was found in the way Linux
 kernel's KVM hypervisor implements the coalesced MMIO write operation.
 It operates on an MMIO ring buffer 'struct kvm_coalesced_mmio' object,
 wherein write indices 'ring->first' and 'ring->last' value could be
 supplied by a host user-space process. An unprivileged host user or
 process with access to '/dev/kvm' device could use this flaw to crash
 the host kernel, resulting in a denial of service or potentially
 escalating privileges on the system (bnc#1151350).

CVE-2019-14835: A buffer overflow flaw was found in the way Linux
 kernel's vhost functionality that translates virtqueue buffers to IOVs,
 logged the buffer descriptors during migration. A privileged guest user
 able to pass descriptors with invalid length to the host when migration
 is underway, could have used this flaw to increase their privileges on
 the host (bnc#1150112).

CVE-2019-15030: In the Linux kernel on the powerpc platform, a local
 user could have read vector registers of other users' processes via a
 Facility Unavailable exception. To exploit the venerability, a local
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.16.1", rls:"SLES15.0SP1"))) {
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

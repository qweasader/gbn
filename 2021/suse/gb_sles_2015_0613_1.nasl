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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0613.1");
  script_cve_id("CVE-2014-3615", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2152");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0613-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0613-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150613-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:0613-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The XEN hypervisor received updates to fix various security issues and bugs.

The following security issues were fixed:
- CVE-2015-2151: XSA-123: A hypervisor memory corruption due to x86
 emulator flaw.
- CVE-2015-2045: XSA-122: Information leak through version information
 hypercall.
- CVE-2015-2044: XSA-121: Information leak via internal x86 system device
 emulation.
- CVE-2015-2152: XSA-119: HVM qemu was unexpectedly enabling emulated VGA
 graphics backends.
- CVE-2014-3615: Information leakage when guest sets high graphics
 resolution.
- CVE-2015-0361: XSA-116: A xen crash due to use after free on hvm guest
 teardown.
- CVE-2014-9065, CVE-2014-9066: XSA-114: xen: p2m lock starvation.

Also the following bugs were fixed:
- bnc#919098 - XEN blktap device intermittently fails to connect
- bnc#882089 - Windows 2012 R2 fails to boot up with greater than 60 vcpus
- bnc#903680 - Problems with detecting free loop devices on Xen guest
 startup
- bnc#861318 - xentop reports 'Found interface vif101.0 but domain 101
 does not exist.'
- Update seabios to rel-1.7.3.1 which is the correct version for Xen 4.4
- Enhancement to virsh/libvirtd 'send-key' command The xen side small fix.
 (FATE#317240)
- bnc#901488 - Intel ixgbe driver assigns rx/tx queues per core resulting
 in irq problems on servers with a large amount of CPU cores
- bnc#910254 - SLES11 SP3 Xen VT-d igb NIC doesn't work
- Add domain_migrate_constraints_set API to Xend's http interface
 (FATE#317239)
- Restore missing fixes from block-dmmd script
- bnc#904255 - XEN boot hangs in early boot on UEFI system
- bsc#912011 - high ping latency after upgrade to latest SLES11SP3 on xen
 Dom0
- Fix missing banner by restoring the figlet program.");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.1_10_k3.12.36_38~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.1_10_k3.12.36_38~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.1_10~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.1_10~9.1", rls:"SLES12.0"))) {
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

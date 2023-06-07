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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3067.1");
  script_cve_id("CVE-2016-7777", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8910", "CVE-2016-9377", "CVE-2016-9378", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9384", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3067-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163067-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:3067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to version 4.7.1 to fix 17 security issues.
These security issues were fixed:
- CVE-2016-9637: ioport array overflow allowing a malicious guest
 administrator can escalate their privilege to that of the host
 (bsc#1011652).
- CVE-2016-9386: x86 null segments were not always treated as unusable
 allowing an unprivileged guest user program to elevate its privilege to
 that of the guest operating system. Exploit of this vulnerability is
 easy on Intel and more complicated on AMD (bsc#1009100).
- CVE-2016-9382: x86 task switch to VM86 mode was mis-handled, allowing a
 unprivileged guest process to escalate its privilege to that of the
 guest operating system on AMD hardware. On Intel hardware a malicious
 unprivileged guest process can crash the guest (bsc#1009103).
- CVE-2016-9385: x86 segment base write emulation lacked canonical address
 checks, allowing a malicious guest administrator to crash the host
 (bsc#1009104).
- CVE-2016-9384: Guest 32-bit ELF symbol table load leaking host data to
 unprivileged guest users (bsc#1009105).
- CVE-2016-9383: The x86 64-bit bit test instruction emulation was broken,
 allowing a guest to modify arbitrary memory leading to arbitrary code
 execution (bsc#1009107).
- CVE-2016-9377: x86 software interrupt injection was mis-handled,
 allowing an unprivileged guest user to crash the guest (bsc#1009108).
- CVE-2016-9378: x86 software interrupt injection was mis-handled,
 allowing an unprivileged guest user to crash the guest (bsc#1009108)
- CVE-2016-9381: Improper processing of shared rings allowing guest
 administrators take over the qemu process, elevating their privilege to
 that of the qemu process (bsc#1009109).
- CVE-2016-9379: Delimiter injection vulnerabilities in pygrub allowed
 guest administrators to obtain the contents of sensitive host files or
 delete the files (bsc#1009111).
- CVE-2016-9380: Delimiter injection vulnerabilities in pygrub allowed
 guest administrators to obtain the contents of sensitive host files or
 delete the files (bsc#1009111).
- CVE-2016-7777: Xen did not properly honor CR0.TS and CR0.EM, which
 allowed local x86 HVM guest OS users to read or modify FPU, MMX, or XMM
 register state information belonging to arbitrary tasks on the guest by
 modifying an instruction while the hypervisor is preparing to emulate it
 (bsc#1000106).
- CVE-2016-8910: The rtl8139_cplus_transmit function in hw/net/rtl8139.c
 allowed local guest OS administrators to cause a denial of service
 (infinite loop and CPU consumption) by leveraging failure to limit the
 ring descriptor count (bsc#1007157).
- CVE-2016-8667: The rc4030_write function in hw/dma/rc4030.c in allowed
 local guest OS administrators to cause a denial of service
 (divide-by-zero error and QEMU process crash) via a large interval timer
 reload value (bsc#1005004).
- CVE-2016-8669: The serial_update_parameters function in hw/char/serial.c
 allowed local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.1_02~25.1", rls:"SLES12.0SP2"))) {
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

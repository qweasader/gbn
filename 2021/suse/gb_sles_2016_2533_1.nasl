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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2533.1");
  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6351", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7154");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2533-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162533-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2533-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.
These security issues were fixed:
- CVE-2014-3672: The qemu implementation in libvirt Xen allowed local
 guest OS users to cause a denial of service (host disk consumption) by
 writing to stdout or stderr (bsc#981264).
- CVE-2016-3158: The xrstor function did not properly handle writes to the
 hardware FSW.ES bit when running on AMD64 processors, which allowed
 local guest OS users to obtain sensitive register content information
 from another guest by leveraging pending exception and mask bits
 (bsc#973188).
- CVE-2016-3159: The fpu_fxrstor function in arch/x86/i387.c did not
 properly handle writes to the hardware FSW.ES bit when running on AMD64
 processors, which allowed local guest OS users to obtain sensitive
 register content information from another guest by leveraging pending
 exception and mask bits (bsc#973188).
- CVE-2016-3710: The VGA module improperly performed bounds checking on
 banked access to video memory, which allowed local guest OS
 administrators to execute arbitrary code on the host by changing access
 modes after setting the bank register, aka the 'Dark Portal' issue
 (bsc#978164)
- CVE-2016-3960: Integer overflow in the x86 shadow pagetable code allowed
 local guest OS users to cause a denial of service (host crash) or
 possibly gain privileges by shadowing a superpage mapping (bsc#974038).
- CVE-2016-4001: Buffer overflow in the stellaris_enet_receive function,
 when the Stellaris ethernet controller is configured to accept large
 packets, allowed remote attackers to cause a denial of service (QEMU
 crash) via a large packet (bsc#975130).
- CVE-2016-4002: Buffer overflow in the mipsnet_receive function, when the
 guest NIC is configured to accept large packets, allowed remote
 attackers to cause a denial of service (memory corruption and QEMU
 crash) or possibly execute arbitrary code via a packet larger than 1514
 bytes (bsc#975138).
- CVE-2016-4020: The patch_instruction function did not initialize the
 imm32 variable, which allowed local guest OS administrators to obtain
 sensitive information from host stack memory by accessing the Task
 Priority Register (TPR) (bsc#975907)
- CVE-2016-4037: The ehci_advance_state function in hw/usb/hcd-ehci.c
 allowed local guest OS administrators to cause a denial of service
 (infinite loop and CPU consumption) via a circular split isochronous
 transfer descriptor (siTD) list (bsc#976111)
- CVE-2016-4439: The esp_reg_write function in the 53C9X Fast SCSI
 Controller (FSC) support did not properly check command buffer length,
 which allowed local guest OS administrators to cause a denial of service
 (out-of-bounds write and QEMU process crash) or potentially execute
 arbitrary code on the host via unspecified vectors (bsc#980716)
- CVE-2016-4441: The get_cmd function in the 53C9X Fast SCSI Controller
 (FSC) support did not properly check DMA length, which allowed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_04_k3.12.60_52.54~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.4_04_k3.12.60_52.54~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.4_04~22.22.2", rls:"SLES12.0"))) {
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

# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1292");
  script_cve_id("CVE-2017-12188", "CVE-2017-12192", "CVE-2017-15299", "CVE-2017-15649", "CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16527", "CVE-2017-16528", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16534", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538");
  script_tag(name:"creation_date", value:"2020-01-23 11:06:04 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 15:46:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2017-1292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1292");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1292");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2017-1292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the key management subsystem of the Linux kernel. An update on an uninstantiated key could cause a kernel panic, leading to denial of service (DoS).(CVE-2017-15299)

It was found that fanout_add() in 'net/packet/af_packet.c' in the Linux kernel, before version 4.13.6, allows local users to gain privileges via crafted system calls that trigger mishandling of packet_fanout data structures, because of a race condition (involving fanout_add and packet_do_bind) that leads to a use-after-free bug.(CVE-2017-15649)

The keyctl_read_key function in security/keys/keyctl.c in the Key Management subcomponent in the Linux kernel before 4.13.5 does not properly consider that a key may be possessed but negatively instantiated, which allows local users to cause a denial of service (OOPS and system crash) via a crafted KEYCTL_READ operation.(CVE-2017-12192)

The Linux kernel built with the KVM visualization support (CONFIG_KVM), with nested visualization(nVMX) feature enabled (nested=1), was vulnerable to a stack buffer overflow issue. The vulnerability could occur while traversing guest page table entries to resolve guest virtual address(gva). An L1 guest could use this flaw to crash the host kernel resulting in denial of service (DoS) or potentially execute arbitrary code on the host to gain privileges on the system.(CVE-2017-12188)

The imon_probe function in drivers/media/rc/imon.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16537)

drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (general protection fault and system crash) or possibly have unspecified other impact via a crafted USB device, related to a missing warm-start check and incorrect attach timing (dm04_lme2510_frontend_attach versus dm04_lme2510_tuner).(CVE-2017-16538)

The cx231xx_usb_probe function in drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16536)

The usb_get_bos_descriptor function in drivers/usb/core/config.c in the Linux kernel before 4.13.10 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16535)

The cdc_parse_cdc_header function in drivers/usb/core/message.c in the Linux kernel before 4.13.6 allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16534)

The usbhid_parse function in drivers/hid/usbhid/hid-core.c in the Linux kernel ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.59.59.46.h33", rls:"EULEROS-2.0SP2"))) {
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

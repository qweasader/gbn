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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1527");
  script_cve_id("CVE-2017-9524", "CVE-2020-10756", "CVE-2020-12829", "CVE-2020-25723");
  script_tag(name:"creation_date", value:"2021-03-05 07:09:21 +0000 (Fri, 05 Mar 2021)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 17:24:00 +0000 (Thu, 29 Oct 2020)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2021-1527)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1527");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1527");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2021-1527 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds read vulnerability was found in the SLiRP networking implementation of the QEMU emulator. This flaw occurs in the icmp6_send_echoreply() routine while replying to an ICMP echo request, also known as ping. This flaw allows a malicious guest to leak the contents of the host memory, resulting in possible information disclosure. This flaw affects versions of libslirp before 4.3.1.(CVE-2020-10756)

In QEMU through 5.0.0, an integer overflow was found in the SM501 display driver implementation. This flaw occurs in the COPY_AREA macro while handling MMIO write operations through the sm501_2d_engine_write() callback. A local attacker could abuse this flaw to crash the QEMU process in sm501_2d_operation() in hw/display/sm501.c on the host, resulting in a denial of service.(CVE-2020-12829)

Quick Emulator (QEMU) built with Network Block Device (NBD) Server support was vulnerable to a null-pointer dereference issue. The flaw could occur when releasing a client that was not initialized due to failed negotiation. A remote user or process could exploit this flaw to crash the qemu-nbd server (denial of service).(CVE-2017-9524)

A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host, resulting in a denial of service.(CVE-2020-25723)");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.465", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.465", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.465", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.465", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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

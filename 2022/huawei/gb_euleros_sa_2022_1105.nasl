# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1105");
  script_cve_id("CVE-2020-25625", "CVE-2020-27617", "CVE-2020-28916", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-0035", "CVE-2021-3527", "CVE-2021-3713");
  script_tag(name:"creation_date", value:"2022-02-13 03:23:50 +0000 (Sun, 13 Feb 2022)");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-01 14:34:55 +0000 (Wed, 01 Sep 2021)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-1105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1105");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1105");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-1105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop when a TD list has a loop.(CVE-2020-25625)

hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.(CVE-2020-28916)

eth_get_gso_type in net/eth.c in QEMU 4.2.1 allows guest OS users to trigger an assertion failure. A guest can crash the QEMU process via packet data that lacks a valid Layer 3 protocol.(CVE-2020-27617)

A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-35504)

A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-35505)

A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a single, large transfer request, to reduce the overhead and improve performance. The combined size of the bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the array length and cause the QEMU process to perform an excessive allocation on the stack, resulting in a denial of service.(CVE-2021-3527)

An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device emulation of QEMU in versions prior to 6.2.0-rc0. The device uses the guest supplied stream number unchecked, which can lead to out-of-bounds access to the UASDevice->data3 and UASDevice->status3 fields. A malicious guest user could use this flaw to crash QEMU or potentially achieve code execution with the privileges of the QEMU process on the host.(CVE-2021-3713)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.493", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.493", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.493", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.493", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2192");
  script_cve_id("CVE-2020-25084", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-20181", "CVE-2021-20221", "CVE-2021-3527", "CVE-2021-3544", "CVE-2021-3545", "CVE-2021-3546");
  script_tag(name:"creation_date", value:"2021-07-13 12:58:53 +0000 (Tue, 13 Jul 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2021-2192)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2192");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2192");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2021-2192 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference flaw was found in the SCSI emulation support of QEMU in versions before 6.0.0. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-35504)

An out-of-bounds heap buffer access issue was found in the ARM Generic Interrupt Controller emulator of QEMU up to and including qemu 4.2.0on aarch64 platform. The issue occurs because while writing an interrupt ID to the controller memory area, it is not masked to be 4 bits wide. It may lead to the said issue while updating controller state fields and their subsequent processing. A privileged guest user may use this flaw to crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-20221)

A flaw was found in the USB redirector device (usb-redir) of QEMU. Small USB packets are combined into a single, large transfer request, to reduce the overhead and improve performance. The combined size of the bulk transfer is used to dynamically allocate a variable length array (VLA) on the stack without proper validation. Since the total size is not bounded, a malicious guest could use this flaw to influence the array length and cause the QEMU process to perform an excessive allocation on the(CVE-2021-3527)

QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not checked.(CVE-2020-25084)

A NULL pointer dereference flaw was found in the am53c974 SCSI host bus adapter emulation of QEMU in versions before 6.0.0. This issue occurs while handling the 'Information Transfer' command. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-35505)

An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit this issue to leak memory from the host. (CVE-2021-3545)

Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime.(CVE-2021-3544)

A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The highest threat from this vulnerability is to data confidentiality and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.1.0~2.9.1.2.285", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~4.1.0~2.9.1.2.285", rls:"EULEROSVIRT-2.9.1"))) {
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

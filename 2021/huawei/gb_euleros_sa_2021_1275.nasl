# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1275");
  script_cve_id("CVE-2020-12829", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-28916");
  script_tag(name:"creation_date", value:"2021-02-05 15:07:31 +0000 (Fri, 05 Feb 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 19:13:00 +0000 (Wed, 24 Feb 2021)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2021-1275)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1275");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1275");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2021-1275 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In QEMU through 5.0.0, an integer overflow was found in the SM501 display driver implementation. This flaw occurs in the COPY_AREA macro while handling MMIO write operations through the sm501_2d_engine_write() callback. A local attacker could abuse this flaw to crash the QEMU process in sm501_2d_operation() in hw/display/sm501.c on the host, resulting in a denial of service.(CVE-2020-12829)

hw/usb/hcd-ohci.c in QEMU 5.0.0 has a stack-based buffer over-read via values obtained from the host controller driver.(CVE-2020-25624)

A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host, resulting in a denial of service.(CVE-2020-25723)

hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop when a TD list has a loop.(CVE-2020-25625)

hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.(CVE-2020-28916)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~4.1.0~16.h4.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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

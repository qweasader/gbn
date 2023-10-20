# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2166");
  script_cve_id("CVE-2016-7907", "CVE-2017-10806", "CVE-2017-11434", "CVE-2017-13711", "CVE-2017-8380", "CVE-2018-11806", "CVE-2018-15746", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-20815", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-9824", "CVE-2020-10756", "CVE-2020-13765", "CVE-2020-14364", "CVE-2020-25084", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-7039", "CVE-2020-7211");
  script_tag(name:"creation_date", value:"2021-07-07 08:44:54 +0000 (Wed, 07 Jul 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-02 23:15:00 +0000 (Tue, 02 Jul 2019)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2021-2166)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2166");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2166");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2021-2166 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The imx_fec_do_tx function in hw/net/imx_fec.c in QEMU (aka Quick Emulator) does not properly limit the buffer descriptor count when transmitting packets, which allows local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) via vectors involving a buffer descriptor with a length of 0 and crafted values in bd.flags.(CVE-2016-7907)
Stack-based buffer overflow in hw/usb/redirect.c in QEMU (aka Quick Emulator) allows local guest OS users to cause a denial of service (QEMU process crash) via vectors related to logging debug messages.(CVE-2017-10806)

The dhcp_decode function in slirp/bootp.c in QEMU (aka Quick Emulator) allows local guest OS users to cause a denial of service (out-of-bounds read and QEMU process crash) via a crafted DHCP options string.(CVE-2017-11434)

A use-after-free issue was found in the Slirp networking implementation of the Quick emulator (QEMU). It occurs when a Socket referenced from multiple packets is freed while responding to a message. A user/process could use this flaw to crash the QEMU process on the host resulting in denial of service.(CVE-2017-13711)

Buffer overflow in the 'megasas_mmio_write' function in Qemu 2.9.0 allows remote attackers to have unspecified impact via unknown vectors.(CVE-2017-8380)

A heap buffer overflow issue was found in the way SLiRP networking back-end in QEMU processes fragmented packets. It could occur while reassembling the fragmented datagrams of an incoming packet. A privileged user/process inside guest could use this flaw to crash the QEMU process resulting in DoS or potentially leverage it to execute arbitrary code on the host with privileges of the QEMU process.(CVE-2018-11806)

qemu-seccomp.c in QEMU might allow local OS guest users to cause a denial of service (guest crash) by leveraging mishandling of the seccomp policy for threads other than the main thread.(CVE-2018-15746)
An integer overflow issue was found in the RTL8139 NIC emulation in QEMU. It could occur while receiving packets over the network if the size value is greater than INT_MAX. Such overflow would lead to stack buffer overflow issue. A user inside guest could use this flaw to crash the QEMU process, resulting in DoS scenario.(CVE-2018-17958)

An integer overflow issue was found in the AMD PC-Net II NIC emulation in QEMU. It could occur while receiving packets, if the size value was greater than INT_MAX. Such overflow would lead to stack buffer overflow issue. A user inside guest could use this flaw to crash the QEMU process resulting in DoS.(CVE-2018-17962)

A heap buffer overflow issue was found in the load_device_tree() function of QEMU, which is invoked to load a device tree blob at boot time. It occurs due to device tree size manipulation before buffer allocation, which could overflow a signed int type. A user/process could use this flaw to potentially execute arbitrary code on a host system ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.2"))) {
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

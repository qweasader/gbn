# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2669");
  script_cve_id("CVE-2019-25162", "CVE-2021-33631", "CVE-2021-46904", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46921", "CVE-2021-46928", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46960", "CVE-2021-46988", "CVE-2021-46999", "CVE-2021-47006", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47054", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47074", "CVE-2021-47076", "CVE-2021-47077", "CVE-2021-47078", "CVE-2021-47082", "CVE-2021-47101", "CVE-2021-47131", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47182", "CVE-2021-47185", "CVE-2021-47203", "CVE-2021-47342", "CVE-2022-48619", "CVE-2022-48626", "CVE-2022-48627", "CVE-2022-48697", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52340", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52458", "CVE-2023-52477", "CVE-2023-52486", "CVE-2023-52515", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52528", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52597", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52646", "CVE-2023-6040", "CVE-2023-6121", "CVE-2023-7192", "CVE-2024-0340", "CVE-2024-0565", "CVE-2024-0607", "CVE-2024-0639", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-23307", "CVE-2024-24855", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26614", "CVE-2024-26640", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26686", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26828", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26872", "CVE-2024-26878", "CVE-2024-26882", "CVE-2024-26884", "CVE-2024-26894", "CVE-2024-26901", "CVE-2024-26915", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26973", "CVE-2024-26976", "CVE-2024-26982", "CVE-2024-26993", "CVE-2024-27008", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27019", "CVE-2024-27046", "CVE-2024-27059", "CVE-2024-27395", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-10-28 04:32:56 +0000 (Mon, 28 Oct 2024)");
  script_version("2024-10-29T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:13:43 +0000 (Thu, 23 May 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2669)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2669");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2669");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2669 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in the routing table size was found in the ICMPv6 handling of Packet Too Big . The size of the routing table is regulated by periodic garbage collection. However, with Packet Too Big Messages it is possible to exceed the routing table size and garbage collector threshold. A user located in the local network or with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up to 95%.(CVE-2023-52340)

In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily : mss = mss * partial_segs, 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final result. Make sure to limit segmentation so that the new mss value is smaller than GSO_BY_FRAGS. (CVE-2023-52435)

In the Linux kernel, the following vulnerability has been resolved: uio: Fix use-after-free in uio_open core-1 core-2 ------------------------------------------------------- uio_unregister_device uio_open idev = idr_find() device_unregister(&idev->dev) put_device(&idev->dev) uio_device_release get_device(&idev->dev) kfree(idev) uio_free_minor(minor) uio_release put_device(&idev->dev) kfree(idev) ------------------------------------------------------- In the core-1 uio_unregister_device(), the device_unregister will kfree idev when the idev->dev kobject ref is 1. But after core-1 device_unregister, put_device and before doing kfree, the core-2 may get_device. Then: 1. After core-1 kfree idev, the core-2 will do use-after-free for idev. 2. When core-2 do uio_release and put_device, the idev will be double freed. To address this issue, we can get idev atomic & inc idev reference with minor_lock.(CVE-2023-52439)

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.(CVE-2024-1086)

In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

In the Linux kernel before 6.4.12, amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c has a fence use-after-free.(CVE-2023-51042)

A flaw was found in the Netfilter subsystem in the Linux kernel. The issue is in the nft_byteorder_eval() function, where the code iterates through a loop and writes to the `dst` array. On each iteration, 8 bytes are written, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h1305.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h1305.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h1305.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h1305.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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

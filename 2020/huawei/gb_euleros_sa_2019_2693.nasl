# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2693");
  script_cve_id("CVE-2015-1350", "CVE-2017-12134", "CVE-2018-1129", "CVE-2018-9465", "CVE-2019-10220", "CVE-2019-15291", "CVE-2019-17351", "CVE-2019-18675", "CVE-2019-18885", "CVE-2019-19051", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19537", "CVE-2019-2215", "CVE-2019-9456");
  script_tag(name:"creation_date", value:"2020-01-23 13:14:14 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 21:05:12 +0000 (Mon, 16 Dec 2019)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-2693)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2693");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2693");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-2693 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory entry lists.(CVE-2019-10220)

A memory leak in the i2400m_op_rfkill_sw_toggle() function in drivers/ net/wimax/i2400m/op-rfkill.c in the Linux kernel before 5.3.11 allows attackers to cause a denial of service (memory consumption), aka CID-6f3ef5c25cc7.(CVE-2019-19051)

A memory leak in the sdma_init() function in drivers/infiniband/hw/hfi1/sdma.c in the Linux kernel before 5.3.9 allows attackers to cause a denial of service (memory consumption) by triggering rhashtable_init() failures, aka CID-34b3be18a04e.(CVE-2019-19065)

Four memory leaks in the acp_hw_init() function in drivers/gpu/drm/amd/amdgpu/amdgpu_acp.c in the Linux kernel before 5.3.8 allow attackers to cause a denial of service (memory consumption) by triggering mfd_add_hotplug_devices() or pm_genpd_add_device() failures, aka CID-57be09c6e874. NOTE: third parties dispute the relevance of this because the attacker must already have privileges for module loading.(CVE-2019-19067)

An issue was discovered in drivers/xen/balloon.c in the Linux kernel before 5.2.3, as used in Xen through 4.12.x, allowing guest OS users to cause a denial of service because of unrestricted resource consumption during the mapping of guest memory, aka CID-6ef36ab967c7.(CVE-2019-17351)

The xen_biovec_phys_mergeable function in drivers/xen/biomerge.c in Xen might allow local OS guest users to corrupt block device data streams and consequently obtain sensitive memory information, cause a denial of service, or gain host OS privileges by leveraging incorrect block IO merge-ability calculation.(CVE-2017-12134)

In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79.(CVE-2019-19523)

In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/misc/iowarrior.c driver, aka CID-edc4746f253d.(CVE-2019-19528)

In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB device in the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef.(CVE-2019-19530)

In the Linux kernel before 5.3.4, there is an info-leak bug that can be caused by a malicious USB device in the drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka CID-a10feaf8c464.(CVE-2019-19533)

In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB device in the USB character device driver layer, aka CID-303911cfc5b9. This affects drivers/usb/core/file.c.(CVE-2019-19537)

In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9.(CVE-2019-19524)

In the Linux kernel before 5.2.10, there is a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.5.h359.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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

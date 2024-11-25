# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2848");
  script_cve_id("CVE-2020-27784", "CVE-2022-0850", "CVE-2022-1462", "CVE-2022-20423", "CVE-2022-21385", "CVE-2022-2663", "CVE-2022-2938", "CVE-2022-2977", "CVE-2022-2991", "CVE-2022-3061", "CVE-2022-3239", "CVE-2022-3303", "CVE-2022-39188", "CVE-2022-39189", "CVE-2022-40307", "CVE-2022-41850", "CVE-2022-42703");
  script_tag(name:"creation_date", value:"2022-12-22 04:14:54 +0000 (Thu, 22 Dec 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 18:37:19 +0000 (Thu, 08 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-2848)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2848");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2848");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-2848 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In rndis_set_response of rndis.c, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege if a malicious USB device is attached with no additional execution privileges needed. User interaction is not needed for exploitation.(CVE-2022-20423)

mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.(CVE-2022-42703)

roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition and resultant use-after-free in certain situations where a report is received while copying a report->value is in progress.(CVE-2022-41850)

A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or member of the audio group) could use this flaw to crash the system, resulting in a denial of service condition(CVE-2022-3303)

A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system or potentially escalate their privileges on the system.(CVE-2022-3239)

An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale TLB entries. This only occurs in situations with VM_PFNMAP VMAs.(CVE-2022-39188)

An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a race condition with a resultant use-after-free.(CVE-2022-40307)

A vulnerability was found in the Linux kernel, where accessing a deallocated instance in printer_ioctl() printer_ioctl() tries to access of a printer_dev instance. However, use-after-free arises because it had been freed by gprinter_free().(CVE-2020-27784)

A flaw in net_rds_alloc_sgs() in Oracle Linux kernels allows unprivileged local users to crash the machine. CVSS 3.1 Base Score 6.2 (Availability impacts).(CVE-2022-21385)

An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED situations.(CVE-2022-39189)

Found Linux Kernel flaw in the i740 driver. The Userspace program could pass any values to the driver through ioctl() interface. The driver doesn't check the value of 'pixclock', so it may cause a divide by zero error.(CVE-2022-3061)

An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted IRC with nf_conntrack_irc configured.(CVE-2022-2663)

A ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.14.h1050.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.14.h1050.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.14.h1050.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.14.h1050.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.14.h1050.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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

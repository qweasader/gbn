# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2244");
  script_cve_id("CVE-2021-33061", "CVE-2021-39686", "CVE-2022-1012", "CVE-2022-1195", "CVE-2022-1652", "CVE-2022-1678", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1789", "CVE-2022-1836", "CVE-2022-1966", "CVE-2022-29581", "CVE-2022-30594", "CVE-2022-32250");
  script_tag(name:"creation_date", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-2244)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2244");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2244");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-2244 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In several functions of binder.c, there is a possible way to represent the wrong domain to SELinux due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.(CVE-2021-39686)

net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.(CVE-2022-32250)

A use-after-free vulnerability was found in the Linux kernel's Netfilter subsystem in net/netfilter/nf_tables_api.c. This flaw allows a local attacker with user access to cause a privilege escalation issue.(CVE-2022-1966)

With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.(CVE-2022-1789)

Due to the small table perturb size, a memory leak flaw was found in the Linux kernel's TCP source port generation algorithm in the net/ipv4/tcp.c function. This flaw allows an attacker to leak information and may cause a denial of service.(CVE-2022-1012)

Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the system.(CVE-2022-1652)

Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18, version 4.14 and later versions.(CVE-2022-29581)

A use-after-free vulnerability was found in drivers/block/floppy.c in the floppy driver module in the Linux kernel between raw_cmd_ioctl and seek_interrupt. This flaw allows an attacker to cause a denial of service, leading to a leak of internal kernel information.(CVE-2022-1836)

An issue was discovered in the Linux Kernel from 4.18 to 4.19, an improper update of sock reference in TCP pacing can lead to memory/netns leak, which can be used by remote clients.(CVE-2022-1678)

A use-after-free flaw was found in the Linux kernel's performance events functionality. A user triggers a race condition in setting up performance monitoring between the leading PERF_TYPE_TRACEPOINT and sub PERF_EVENT_HARDWARE plus the PERF_EVENT_SOFTWARE using the perf_event_open() function with these three types. This flaw allows a local user to crash the system.(CVE-2022-1729)

A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use after free both read or write when non synchronized between cleanup routine and firmware download routine.(CVE-2022-1734)

The Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2204.1.0.h1160.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2204.1.0.h1160.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2204.1.0.h1160.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2204.1.0.h1160.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2204.1.0.h1160.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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

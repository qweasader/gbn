# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1533");
  script_cve_id("CVE-2013-4515", "CVE-2013-6378", "CVE-2014-0196", "CVE-2014-3673", "CVE-2014-3690", "CVE-2014-9715", "CVE-2014-9731", "CVE-2015-2672", "CVE-2015-6937", "CVE-2015-7613", "CVE-2015-8844", "CVE-2016-0821", "CVE-2016-2066", "CVE-2016-6156", "CVE-2017-1000251", "CVE-2017-18200", "CVE-2017-2671", "CVE-2018-10883", "CVE-2018-15594", "CVE-2018-5344");
  script_tag(name:"creation_date", value:"2020-01-23 12:07:12 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 13:29:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1533");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1533");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw was found in the way the Linux kernel's netfilter connection tracking implementation loaded extensions. An attacker on a local network could potentially send a sequence of specially crafted packets that would initiate the loading of a large number of extensions, causing the targeted system in that network to crash.(CVE-2014-9715)

A flaw was found in the Linux kernel which could cause a kernel panic when restoring machine specific registers on the PowerPC platform. Incorrect transactional memory state registers could inadvertently change the call path on return from userspace and cause the kernel to enter an unknown state and crash.(CVE-2015-8844)

A timing flaw was found in the Chrome EC driver in the Linux kernel. An attacker could abuse timing to skip validation checks to copy additional data from userspace possibly increasing privilege or crashing the system.(CVE-2016-6156)

A race condition flaw was found in the way the Linux kernel's IPC subsystem initialized certain fields in an IPC object structure that were later used for permission checking before inserting the object into a globally visible list. A local, unprivileged user could potentially use this flaw to elevate their privileges on the system.(CVE-2015-7613)

A path length checking flaw was found in Linux kernels built with UDF file system (CONFIG_UDF_FS) support. An attacker able to mount a corrupted/malicious UDF file system image could use this flaw to leak kernel memory to user-space.(CVE-2014-9731)

A race condition leading to a NULL pointer dereference was found in the Linux kernel's Link Layer Control implementation. A local attacker with access to ping sockets could use this flaw to crash the system.(CVE-2017-2671)

The f2fs implementation in the Linux kernel, before 4.14, mishandles reference counts associated with f2fs_wait_discard_bios calls. This allows local users to cause a denial of service (BUG), as demonstrated by fstrim.(CVE-2017-18200)

The LIST_POISON feature in include/linux/poison.h in the Linux kernel before 4.3, as used in Android 6.0.1 before 2016-03-01, does not properly consider the relationship to the mmap_min_addr value, which makes it easier for attackers to bypass a poison-pointer protection mechanism by triggering the use of an uninitialized list entry, aka Android internal bug 26186802, a different vulnerability than CVE-2015-3636.(CVE-2016-0821)

The xsave/xrstor implementation in arch/x86/include/asm/xsave.h in the Linux kernel before 3.19.2 creates certain .altinstr_replacement pointers and consequently does not provide any protection against instruction faulting, which allows local users to cause a denial of service (panic) by triggering a fault, as demonstrated by an unaligned memory operand or a non-canonical address memory operand.(CVE-2015-2672)

The n_tty_write function in drivers/tty/n_tty.c in the Linux kernel through 3.14.3 does not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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

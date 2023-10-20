# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1635");
  script_cve_id("CVE-2012-2744", "CVE-2012-3400", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-6282", "CVE-2017-0786", "CVE-2018-20836", "CVE-2018-7191", "CVE-2019-11190", "CVE-2019-11486", "CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11810", "CVE-2019-11811");
  script_tag(name:"creation_date", value:"2020-01-23 12:17:55 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 02:22:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1635");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1635");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the Linux kernel before 4.20. There is a race condition in smp_task_timedout() and smp_task_done() in drivers/scsi/libsas/sas_expander.c, leading to a use-after-free.(CVE-2018-20836)

The Linux kernel before 4.8 allows local users to bypass ASLR on setuid programs (such as /bin/su) because install_exec_creds() is called too late in load_elf_binary() in fs/binfmt_elf.c, and thus the ptrace_may_access() check has a race condition when reading /proc/pid/stat.(CVE-2019-11190)

The Siemens R3964 line discipline driver in drivers/tty
_r3964.c in the Linux kernel before 5.0.8 has multiple race conditions.(CVE-2019-11486)

The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c, include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can occur with FUSE requests.(CVE-2019-11487)

The coredump implementation in the Linux kernel before 5.0.10 does not use locking or other mechanisms to prevent vma layout or vma flags changes while it runs, which allows local users to obtain sensitive information, cause a denial of service, or possibly have unspecified other impact by triggering a race condition with mmget_not_zero or get_task_mm calls. This is related to fs/userfaultfd.c, mm/mmap.c, fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c.(CVE-2019-11599)

An issue was discovered in the Linux kernel before 5.0.7. A NULL pointer dereference can occur when megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This causes a Denial of Service, related to a use-after-free.(CVE-2019-11810)

In the tun subsystem in the Linux kernel before 4.13.14, dev_get_valid_name is not called before register_netdevice. This allows local users to cause a denial of service (NULL pointer dereference and panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. This is similar to CVE-2013-4343.(CVE-2018-7191)

net/ipv6
etfilter
f_conntrack_reasm.c in the Linux kernel before 2.6.34, when the nf_conntrack_ipv6 module is enabled, allows remote attackers to cause a denial of service (NULL pointer dereference and system crash) via certain types of fragmented IPv6 packets.(CVE-2012-2744)

Heap-based buffer overflow in the udf_load_logicalvol function in fs/udf/super.c in the Linux kernel before 3.4.5 allows remote attackers to cause a denial of service (system crash) or possibly have unspecified other impact via a crafted UDF filesystem.(CVE-2012-3400)

The mmc_ioctl_cdrom_read_data function in drivers/cdrom/cdrom.c in the Linux kernel through 3.10 allows local users to obtain sensitive information from kernel memory via a read operation on a malfunctioning CD-ROM drive.(CVE-2013-2164)

The (1) get_user and (2) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~1.2.159", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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

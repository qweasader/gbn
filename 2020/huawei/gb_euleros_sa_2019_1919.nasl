# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1919");
  script_cve_id("CVE-2018-10323", "CVE-2018-10879", "CVE-2018-10883", "CVE-2018-13406", "CVE-2018-15594", "CVE-2018-16871", "CVE-2018-20856", "CVE-2019-12378", "CVE-2019-12381", "CVE-2019-12382", "CVE-2019-12614", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2020-01-23 12:26:36 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-01 13:27:52 +0000 (Thu, 01 Aug 2019)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1919)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1919");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1919");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1919 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The xfs_bmap_extents_to_btree function in fs/xfs/libxfs/xfs_bmap.c in the Linux kernel through 4.16.3 allows local users to cause a denial of service (xfs_bmapi_write NULL pointer dereference) via a crafted xfs image.(CVE-2018-10323)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause a use-after-free in ext4_xattr_set_entry function and a denial of service or unspecified other impact may occur by renaming a file in a crafted ext4 filesystem image.(CVE-2018-10879)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bound write in jbd2_journal_dirty_metadata(), a denial of service, and a system crash by mounting and operating on a crafted ext4 filesystem image. (CVE-2018-10883)

The Linux kernel was found vulnerable to an integer overflow in the drivers/video/fbdev/uvesafb.c:uvesafb_setcmap() function. The vulnerability could result in local attackers being able to crash the kernel or potentially elevate privileges.(CVE-2018-13406)

It was found that paravirt_patch_call/jump() functions in the arch/x86/kernel/paravirt.c in the Linux kernel mishandles certain indirect calls, which makes it easier for attackers to conduct Spectre-v2 attacks against paravirtualized guests. (CVE-2018-15594)

A flaw was found in the Linux kernel's NFS implementation. An attacker, who is able to mount an exported NFS filesystem, is able to trigger a null pointer dereference by using an invalid NFS sequence. This can panic the machine and deny access to the NFS server. Any outstanding disk writes to the NFS server will be lost. (CVE-2018-16871)

A vulnerability was found in the Linux kernel's floppy disk driver implementation. A local attacker with access to the floppy device could call set_geometry in drivers/block/floppy.c, which does not validate the sect and head fields, causing an integer overflow and out-of-bounds read. This flaw may crash the system or allow an attacker to gather information causing subsequent successful attacks. (CVE-2019-14283)

A vulnerability was found in the Linux kernel's floppy disk driver implementation. A local attacker with access to the floppy disk device file (/dev/fd0 through to /dev/fdN) can create a situation that causes the kernel to divide by zero. This requires two consecutive ioctl calls to be issued. The first ioctl call sets the sector and rate values, and the second ioctl is the call to format the floppy disk to the appropriate values. This flaw can cause the system to divide by zero and panic the host. No media (floppy) is required to be inserted for this attack to work properly.(CVE-2019-14284)

In the Linux kernel through 5.2.1 on the powerpc platform, when hardware transactional memory is disabled, a local user can cause a denial of service (TM Bad Thing exception and system crash) via a sigreturn() system call that sends a crafted signal frame. This affects ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.2.h239.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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

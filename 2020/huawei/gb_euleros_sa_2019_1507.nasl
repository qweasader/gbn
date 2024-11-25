# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1507");
  script_cve_id("CVE-2018-10124", "CVE-2018-10322", "CVE-2018-1066", "CVE-2018-10675", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10881", "CVE-2018-10883", "CVE-2018-1092", "CVE-2018-1094", "CVE-2018-10940");
  script_tag(name:"creation_date", value:"2020-01-23 11:59:44 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-21 19:02:31 +0000 (Fri, 21 Sep 2018)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1507");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1507");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Linux kernel has an undefined behavior when an argument of INT_MIN is passed to the kernel/signal.c:kill_something_info() function. A local attacker may be able to exploit this to cause a denial of service.(CVE-2018-10124)

The xfs_dinode_verify function in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel can cause a NULL pointer dereference in xfs_ilock_attr_map_shared function. An attacker could trick a legitimate user or a privileged attacker could exploit this by mounting a crafted xfs filesystem image to cause a kernel panic and thus a denial of service.(CVE-2018-10322)

A flaw was found in the Linux kernel's client-side implementation of the cifs protocol. This flaw allows an attacker controlling the server to kernel panic a client which has the CIFS server mounted.(CVE-2018-1066)

The do_get_mempolicy() function in mm/mempolicy.c in the Linux kernel allows local users to hit a use-after-free bug via crafted system calls and thus cause a denial of service (DoS) or possibly have unspecified other impact. Due to the nature of the flaw, privilege escalation cannot be fully ruled out.(CVE-2018-10675)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bounds write and a denial of service or unspecified other impact is possible by mounting and operating a crafted ext4 filesystem image.(CVE-2018-10878)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause a use-after-free in ext4_xattr_set_entry function and a denial of service or unspecified other impact may occur by renaming a file in a crafted ext4 filesystem image.(CVE-2018-10879)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bound access in ext4_get_group_info function, a denial of service, and a system crash by mounting and operating on a crafted ext4 filesystem image.(CVE-2018-10881)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bound write in jbd2_journal_dirty_metadata(), a denial of service, and a system crash by mounting and operating on a crafted ext4 filesystem image.(CVE-2018-10883)

The Linux kernel is vulnerable to a NULL pointer dereference in the ext4/mballoc.c:ext4_process_freed_data() function. An attacker could trick a legitimate user or a privileged attacker could exploit this by mounting a crafted ext4 image to cause a kernel panic.(CVE-2018-1092)

The Linux kernel is vulnerable to a NULL pointer dereference in the ext4/xattr.c:ext4_xattr_inode_hash() function. An attacker could trick a legitimate user or a privileged attacker could exploit this to cause a NULL pointer dereference with a crafted ext4 image.(CVE-2018-1094)

A flaw was found in the Linux kernel, before 4.16.6 where the cdrom_ioctl_media_changed function in drivers/cdrom/cdrom.c allows local attackers to use a incorrect bounds check in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read out kernel memory.(CVE-2018-10940)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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

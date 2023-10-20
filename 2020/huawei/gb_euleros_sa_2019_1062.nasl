# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1062");
  script_cve_id("CVE-2017-18208", "CVE-2017-18255", "CVE-2017-18270", "CVE-2017-7889", "CVE-2018-10021", "CVE-2018-1066", "CVE-2018-10940", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-13053", "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-14734", "CVE-2018-7757", "CVE-2018-7995");
  script_tag(name:"creation_date", value:"2020-01-23 11:29:33 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 21:12:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1062");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1062");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Missing check in fs/inode.c:inode_init_owner() does not clear SGID bit on non-directories for non-members.(CVE-2018-13405)

A null pointer dereference in dccp_write_xmit() function in net/dccp/output.c in the Linux kernel allows a local user to cause a denial of service by a number of certain crafted system calls.(CVE-2018-1130)

A flaw was found in the Linux kernel, before 4.16.6 where the cdrom_ioctl_media_changed function in drivers/cdrom/cdrom.c allows local attackers to use a incorrect bounds check in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read out kernel memory.(CVE-2018-10940)

The madvise_willneed function in the Linux kernel allows local users to cause a denial of service (infinite loop) by triggering use of MADVISE_WILLNEED for a DAX mapping.(CVE-2017-18208)

fuse-backed file mmap-ed onto process cmdline arguments causes denial of service.(CVE-2018-1120)

Memory leak in the sas_smp_get_phy_events function in drivers/scsi/libsas/sas_expander.c in the Linux kernel allows local users to cause a denial of service (kernel memory exhaustion) via multiple read accesses to files in the /sys/class/sas_phy directory.(CVE-2018-7757)

A vulnerability was found in the Linux kernel's kernel/events/core.c:perf_cpu_time_max_percent_handler() function. Local privileged users could exploit this flaw to cause a denial of service due to integer overflow or possibly have unspecified other impact.(CVE-2017-18255)

A flaw was found in the Linux kernel in the way a local user could create keyrings for other users via keyctl commands. This may allow an attacker to set unwanted defaults, a denial of service, or possibly leak keyring information between users.(CVE-2017-18270)

The mm subsystem in the Linux kernel through 4.10.10 does not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism, which allows local users to read or write to kernel memory locations in the first megabyte (and bypass slab-allocation access restrictions) via an application that opens the /dev/mem file, related to arch/x86/mm/init.c and drivers/char/mem.c.(CVE-2017-7889)

The code in the drivers/scsi/libsas/sas_scsi_host.c file in the Linux kernel allow a physically proximate attacker to cause a memory leak in the ATA command queue and, thus, denial of service by triggering certain failure conditions.(CVE-2018-10021)

A flaw was found in the Linux kernel's client-side implementation of the cifs protocol. This flaw allows an attacker controlling the server to kernel panic a client which has the CIFS server mounted.(CVE-2018-1066)

A flaw was found in the alarm_timer_nsleep() function in kernel/time/alarmtimer.c in the Linux kernel. The ktime_add_safe() function is not used and an integer overflow can happen causing an alarm not to fire or possibly a denial-of-service if using a large relative timeout.(CVE-2018-13053)

An issue was discovered in the XFS filesystem in fs/xfs/libxfs/xfs_attr_leaf.c in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.62.59.83.h128", rls:"EULEROS-2.0SP2"))) {
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

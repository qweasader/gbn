# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1587");
  script_cve_id("CVE-2018-1000204", "CVE-2018-10882", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-16884", "CVE-2018-18710", "CVE-2018-19985", "CVE-2018-20511", "CVE-2018-9516", "CVE-2018-9568", "CVE-2019-11091", "CVE-2019-11190", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-7222", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2020-01-23 12:16:07 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-16 10:49:00 +0000 (Tue, 16 May 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1587)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1587");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1587");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1587 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A malformed SG_IO ioctl issued for a SCSI device in the Linux kernel leads to a local kernel data leak manifesting in up to approximately 1000 memory pages copied to the userspace. The problem has limited scope as non-privileged users usually have no permissions to access SCSI device files.(CVE-2018-1000204)

A flaw in the load_elf_binary() function in the Linux kernel allows a local attacker to leak the base address of .text and stack sections for setuid binaries and bypass ASLR because install_exec_creds() is called too late in this function.(CVE-2019-11190)

A flaw was found in the Linux kernel in the hid_debug_events_read() function in the drivers/hid/hid-debug.c file. A lack of the certain checks may allow a privileged user ('root') to achieve an out-of-bounds write and thus receiving user space buffer corruption.(CVE-2018-9516)

A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out.(CVE-2018-16884)

An issue was discovered in the Linux kernel through 4.19. An information leak in cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from unsigned long to int interferes with bounds checking. This is similar to CVE-2018-10940 and CVE-2018-16658.(CVE-2018-18710)

A flaw was found in the Linux kernel in the function hso_probe() which reads if_num value from the USB device (as an u8) and uses it without a length check to index an array, resulting in an OOB memory read in hso_probe() or hso_get_config_data(). An attacker with a forged USB device and physical access to a system (needed to connect such a device) can cause a system crash and a denial of service.(CVE-2018-19985)

A possible memory corruption due to a type confusion was found in the Linux kernel in the sk_clone_lock() function in the net/core/sock.c. The possibility of local escalation of privileges cannot be fully ruled out for a local unprivileged attacker.(CVE-2018-9568)

A flaw was found in the Linux kernels implementation of Logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack. An attacker with physical access within the range of standard Bluetooth transmission can create a specially crafted packet. The response to this specially crafted packet can contain part of the kernel stack which can be used in a further attack.(CVE-2019-3459)

A flaw was found in the Linux kernel's implementation of logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack in the l2cap_parse_conf_rsp and l2cap_parse_conf_req functions. An attacker with physical access within the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~514.44.5.10.h193", rls:"EULEROS-2.0SP3"))) {
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

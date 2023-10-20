# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1481");
  script_cve_id("CVE-2014-4171", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5045", "CVE-2014-5077", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-6416", "CVE-2014-6417", "CVE-2014-6418", "CVE-2014-7145", "CVE-2014-7283", "CVE-2014-7825", "CVE-2014-7826");
  script_tag(name:"creation_date", value:"2020-01-23 11:52:15 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:19:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1481");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1481");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition flaw was found in the way the Linux kernel's mmap(2), madvise(2), and fallocate(2) system calls interacted with each other while operating on virtual memory file system files. A local user could use this flaw to cause a denial of service.(CVE-2014-4171)

An information leak flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled access of the user control's state. A local, privileged user could use this flaw to leak kernel memory to user space.(CVE-2014-4652)

A use-after-free flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled user controls. A local, privileged user could use this flaw to crash the system.(CVE-2014-4653)

A use-after-free flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled user controls. A local, privileged user could use this flaw to crash the system.(CVE-2014-4654)

A use-after-free flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled user controls. A local, privileged user could use this flaw to crash the system.(CVE-2014-4655)

An integer overflow flaw was found in the way the Linux kernel's Advanced Linux Sound Architecture (ALSA) implementation handled user controls. A local, privileged user could use this flaw to crash the system.(CVE-2014-4656)

An integer underflow flaw was found in the way the Linux kernel's Stream Control Transmission Protocol (SCTP) implementation processed certain COOKIE_ECHO packets. By sending a specially crafted SCTP packet, a remote attacker could use this flaw to prevent legitimate connections to a particular SCTP server socket to be made.(CVE-2014-4667)

'It was found that the Linux kernel's ptrace subsystem allowed a traced process' instruction pointer to be set to a non-canonical memory address without forcing the non-sysret code path when returning to user space. A local, unprivileged user could use this flaw to crash the system or, potentially, escalate their privileges on the system.
Note: The CVE-2014-4699 issue only affected systems using an Intel CPU.(CVE-2014-4699)'

A flaw was found in the way the pppol2tp_setsockopt() and pppol2tp_getsockopt() functions in the Linux kernel's PPP over L2TP implementation handled requests with a non-SOL_PPPOL2TP socket option level. A local, unprivileged user could use this flaw to escalate their privileges on the system.(CVE-2014-4943)

A flaw was found in the way the Linux kernel's VFS subsystem handled reference counting when performing unmount operations on symbolic links. A local, unprivileged user could use this flaw to exhaust all available memory on the system or, potentially, trigger a use-after-free error, resulting in a system crash or privilege escalation.(CVE-2014-5045)

A NULL pointer dereference flaw was found in the way the ... [Please see the references for more information on the vulnerabilities]");

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

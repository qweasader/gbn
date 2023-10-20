# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0333.1");
  script_cve_id("CVE-2004-0230", "CVE-2012-6704", "CVE-2013-4312", "CVE-2015-1350", "CVE-2015-7513", "CVE-2015-7833", "CVE-2015-8956", "CVE-2015-8962", "CVE-2015-8964", "CVE-2016-0823", "CVE-2016-10088", "CVE-2016-1583", "CVE-2016-2187", "CVE-2016-2189", "CVE-2016-3841", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5829", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7117", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7916", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-8633", "CVE-2016-8646", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9685", "CVE-2016-9756", "CVE-2016-9793", "CVE-2017-5551");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:01 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170333-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 LTSS kernel was updated to receive various security and bugfixes.
This is the last planned LTSS kernel update for the SUSE Linux Enterprise Server 11 SP2 LTSS.
The following security bugs were fixed:
- CVE-2016-10088: The sg implementation in the Linux kernel did not
 properly restrict write operations in situations where the KERNEL_DS
 option is set, which allowed local users to read or write to arbitrary
 kernel memory locations or cause a denial of service (use-after-free) by
 leveraging access to a /dev/sg device, related to block/bsg.c and
 drivers/scsi/sg.c. NOTE: this vulnerability exists because of an
 incomplete fix for CVE-2016-9576 (bnc#1017710).
- CVE-2004-0230: TCP, when using a large Window Size, made it easier for
 remote attackers to guess sequence numbers and cause a denial of service
 (connection loss) to persistent TCP connections by repeatedly injecting
 a TCP RST packet, especially in protocols that use long-lived
 connections, such as BGP (bnc#969340).
- CVE-2016-8632: The tipc_msg_build function in net/tipc/msg.c in the
 Linux kernel did not validate the relationship between the minimum
 fragment length and the maximum packet size, which allowed local users
 to gain privileges or cause a denial of service (heap-based buffer
 overflow) by leveraging the CAP_NET_ADMIN capability (bnc#1008831).
- CVE-2016-8399: An out of bounds read in the ping protocol handler could
 have lead to information disclosure (bsc#1014746).
- CVE-2016-9793: The sock_setsockopt function in net/core/sock.c in the
 Linux kernel mishandled negative values of sk_sndbuf and sk_rcvbuf,
 which allowed local users to cause a denial of service (memory
 corruption and system crash) or possibly have unspecified other impact
 by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt
 system call with the (1) SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option
 (bnc#1013531).
- CVE-2012-6704: The sock_setsockopt function in net/core/sock.c in the
 Linux kernel mishandled negative values of sk_sndbuf and sk_rcvbuf,
 which allowed local users to cause a denial of service (memory
 corruption and system crash) or possibly have unspecified other impact
 by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt
 system call with the (1) SO_SNDBUF or (2) SO_RCVBUF option (bnc#1013542).
- CVE-2016-9756: arch/x86/kvm/emulate.c in the Linux kernel did not
 properly initialize Code Segment (CS) in certain error cases, which
 allowed local users to obtain sensitive information from kernel stack
 memory via a crafted application (bnc#1013038).
- CVE-2016-3841: The IPv6 stack in the Linux kernel mishandled options
 data, which allowed local users to gain privileges or cause a denial of
 service (use-after-free and system crash) via a crafted sendmsg system
 call (bnc#992566).
- CVE-2016-9685: Multiple memory leaks in error paths in
 fs/xfs/xfs_attr_list.c ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.7.53.1", rls:"SLES11.0SP2"))) {
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

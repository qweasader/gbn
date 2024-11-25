# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0825.1");
  script_cve_id("CVE-2017-13672", "CVE-2018-10839", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19966", "CVE-2018-19967", "CVE-2019-6778", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0825-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190825-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:0825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security issues fixed:
CVE-2018-18849: Fixed an out of bounds memory access issue that was
 found in the LSI53C895A SCSI Host Bus Adapter emulation while writing a
 message in lsi_do_msgin. It could occur during migration if the
 'msg_len' field has an invalid value. A user/process could use this flaw
 to crash the Qemu process resulting in DoS (bsc#1114423).

CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up the
 host, resulting in a Denial of Service (DoS). (XSA-282) (bsc#1114988)

CVE-2018-19665: Fixed an integer overflow in Bluetooth routines allows
 memory corruption (bsc#1117756).

CVE-2018-18438: Fixed an integer overflow in ccid_card_vscard_read
 function which allows memory corruption (bsc#1112188).

CVE-2018-17962: Fixed a Buffer Overflow in pcnet_receive in
 hw/net/pcnet.c because an incorrect integer data type is used
 (bsc#1111011).

Fixed an issue which could allow a malicious unprivileged guest
 userspace process to escalate its privilege to that of other userspace
 processes in the same guest and potentially thereby to that
 of the guest operating system (bsc#1126201).

CVE-2018-19961 CVE-2018-19962: Fixed insufficient TLB flushing /
 improper large page mappings with AMD IOMMUs (XSA-275)(bsc#1115040).

CVE-2018-17963: Fixed qemu_deliver_packet_iov in net/net.c that accepts
 packet sizes greater than INT_MAX, which allows attackers to cause a
 denial of service or possibly have unspecified other impact.
 (bsc#1111014)

Fixed an issue which could allow an untrusted PV domain with access to a
 physical device to DMA into its own pagetables leading to privilege
 escalation (bsc#1126195).

Fixed an issue which could allow a malicious or buggy x86 PV guest
 kernels can mount a Denial of Service attack affecting the whole system
 (bsc#1126196)

CVE-2018-17958: Fixed a Buffer Overflow in rtl8139_do_receive in
 hw/net/rtl8139.c because an incorrect integer data type is used
 (bsc#1111007).

CVE-2018-10839: Fixed an integer overflow which could lead to a buffer
 overflow issue (bsc#1110924).

CVE-2019-6778: Fixed a heap buffer overflow in tcp_emu() found in slirp
 (bsc#1123157).

CVE-2018-19966: Fixed issue introduced by XSA-240 that could have caused
 conflicts with shadow paging (XSA-280)(bsc#1115047).

CVE-2017-13672: Fixed an out of bounds read access during display update
 (bsc#1056336).

Fixed multiple access violations introduced by XENMEM_exchange hypercall
 which could allow a single PV guest to leak arbitrary amounts of memory,
 leading to a denial of service (bsc#1126192).

Fixed an issue which could allow malicious or buggy guests with passed
 through PCI devices to be able to escalate their privileges, crash the
 host, or access data belonging to other guests. Additionally memory
 leaks were also possible (bsc#1126140).

Fixed a race condition issue which could allow malicious PV ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.5_28_k3.12.74_60.64.107~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.5.5_28_k3.12.74_60.64.107~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.5.5_28~22.58.1", rls:"SLES12.0SP1"))) {
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

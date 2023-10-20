# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3503.1");
  script_cve_id("CVE-2017-18204", "CVE-2019-19063", "CVE-2019-6133", "CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-14381", "CVE-2020-14390", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25705", "CVE-2020-26088", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:00:00 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3503-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3503-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203503-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3503-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bug fixes.


The following security bugs were fixed:

CVE-2020-25705: A flaw in the way reply ICMP packets are limited in was
 found that allowed to quickly scan open UDP ports. This flaw allowed an
 off-path remote user to effectively bypassing source port UDP
 randomization. The highest threat from this vulnerability is to
 confidentiality and possibly integrity, because software and services
 that rely on UDP source port randomization (like DNS) are indirectly
 affected as well. Kernel versions may be vulnerable to this issue
 (bsc#1175721, bsc#1178782).

CVE-2020-25668: Fixed a use-after-free in con_font_op() (bsc#1178123).

CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl
 (bnc#1177766).

CVE-2020-14351: Fixed a race in the perf_mmap_close() function
 (bsc#1177086).

CVE-2020-8694: Restricted energy meter to root access (bsc#1170415).

CVE-2020-12352: Fixed an information leak when processing certain AMP
 packets aka 'BleedingTooth' (bsc#1177725).

CVE-2020-25645: Fixed an issue which traffic between two Geneve
 endpoints may be unencrypted when IPsec is configured to encrypt traffic
 for the specific UDP port used by the GENEVE tunnel allowing anyone
 between the two endpoints to read the traffic unencrypted (bsc#1177511).

CVE-2020-14381: Fixed a use-after-free in the fast user mutex (futex)
 wait operation, which could have lead to memory corruption and possibly
 privilege escalation (bsc#1176011).

CVE-2020-25212: Fixed A TOCTOU mismatch in the NFS client code which
 could have been used by local attackers to corrupt memory (bsc#1176381).

CVE-2020-14390: Fixed an out-of-bounds memory write leading to memory
 corruption or a denial of service when changing screen size
 (bnc#1176235).

CVE-2020-25643: Fixed a memory corruption and a read overflow which
 could have caused by improper input validation in the ppp_cp_parse_cr
 function (bsc#1177206).

CVE-2020-25641: Fixed a zero-length biovec request issued by the block
 subsystem could have caused the kernel to enter an infinite loop,
 causing a denial of service (bsc#1177121).

CVE-2020-26088: Fixed an improper CAP_NET_RAW check in NFC socket
 creation could have been used by local attackers to create raw sockets,
 bypassing security mechanisms (bsc#1176990).

CVE-2020-0432: Fixed an out of bounds write due to an integer overflow
 (bsc#1176721).

CVE-2020-0431: Fixed an out of bounds write due to a missing bounds
 check (bsc#1176722).

CVE-2020-0427: Fixed an out of bounds read due to a use after free
 (bsc#1176725).

CVE-2020-0404: Fixed a linked list corruption due to an unusual root
 cause (bsc#1176423).

CVE-2020-25284: Fixed an incomplete permission checking for access to
 rbd devices, which could have been leveraged by local attackers to map
 or unmap rbd block devices (bsc#1176482).

CVE-2019-19063: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.135.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_135-default", rpm:"kgraft-patch-4_4_180-94_135-default~1~4.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_135-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_135-default-debuginfo~1~4.5.1", rls:"SLES12.0SP3"))) {
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

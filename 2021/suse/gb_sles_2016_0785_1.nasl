# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0785.1");
  script_cve_id("CVE-2013-7446", "CVE-2015-5707", "CVE-2015-8709", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-2069", "CVE-2016-2384");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160785-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:0785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.55 to receive various security and bugfixes.
Features added:
- A improved XEN blkfront module was added, which allows more I/O
 bandwidth. (FATE#320625) It is called xen-blkfront in PV, and
 xen-vbd-upstream in HVM mode.
The following security bugs were fixed:
- CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in the
 Linux kernel allowed local users to bypass intended AF_UNIX socket
 permissions or cause a denial of service (panic) via crafted epoll_ctl
 calls (bnc#955654).
- CVE-2015-5707: Integer overflow in the sg_start_req function in
 drivers/scsi/sg.c in the Linux kernel allowed local users to cause a
 denial of service or possibly have unspecified other impact via a large
 iov_count value in a write request (bnc#940338).
- CVE-2015-8709: kernel/ptrace.c in the Linux kernel mishandled uid and
 gid mappings, which allowed local users to gain privileges by
 establishing a user namespace, waiting for a root process to enter that
 namespace with an unsafe uid or gid, and then using the ptrace system
 call. NOTE: the vendor states 'there is no kernel bug here' (bnc#959709
 bnc#960561).
- CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux kernel did not
 properly manage the relationship between a lock and a socket, which
 allowed local users to cause a denial of service (deadlock) via a
 crafted sctp_accept call (bnc#961509).
- CVE-2015-8785: The fuse_fill_write_pages function in fs/fuse/file.c in
 the Linux kernel allowed local users to cause a denial of service
 (infinite loop) via a writev system call that triggers a zero length for
 the first segment of an iov (bnc#963765).
- CVE-2015-8812: A use-after-free flaw was found in the CXGB3 kernel
 driver when the network was considered to be congested. This could be
 used by local attackers to cause machine crashes or potentially code
 executuon (bsc#966437).
- CVE-2016-0723: Race condition in the tty_ioctl function in
 drivers/tty/tty_io.c in the Linux kernel allowed local users to obtain
 sensitive information from kernel memory or cause a denial of service
 (use-after-free and system crash) by making a TIOCGETD ioctl call during
 processing of a TIOCSETD ioctl call (bnc#961500).
- CVE-2016-0774: A pipe buffer state corruption after unsuccessful atomic
 read from pipe was fixed (bsc#964730).
- CVE-2016-2069: Race conditions in TLB syncing was fixed which could leak
 to information leaks (bnc#963767).
- CVE-2016-2384: A double-free triggered by invalid USB descriptor in ALSA
 usb-audio was fixed, which could be exploited by physical local
 attackers to crash the kernel or gain code execution (bnc#966693).
The following non-security bugs were fixed:
- alsa: rawmidi: Make snd_rawmidi_transmit() race-free (bsc#968018).
- alsa: seq: Fix leak of pool buffer at concurrent writes (bsc#968018).
- be2net: fix some log messages (bnc#855062 FATE#315961, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.55~52.42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.55~52.42.1", rls:"SLES12.0"))) {
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

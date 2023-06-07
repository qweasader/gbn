# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851515");
  script_version("2022-11-04T10:11:50+0000");
  script_tag(name:"last_modification", value:"2022-11-04 10:11:50 +0000 (Fri, 04 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-02-23 05:05:46 +0100 (Thu, 23 Feb 2017)");
  script_cve_id("CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 02:25:00 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for kernel (openSUSE-SU-2017:0541-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 42.2 kernel was updated
  to 4.4.49 to receive various security and bugfixes.

  The following security bugs were fixed:

  - CVE-2017-5986: A userlevel triggerable BUG_ON on sctp_wait_for_sndbuf
  was fixed. (bsc#1025235)

  - CVE-2017-5970: The ipv4_pktinfo_prepare function in
  net/ipv4/ip_sockglue.c in the Linux kernel allowed attackers to cause a
  denial of service (system crash) via (1) an application that made
  crafted system calls or possibly (2) IPv4 traffic with invalid IP
  options (bnc#1024938).

  - CVE-2017-5897: A potential remote denial of service within the IPv6 GRE
  protocol was fixed. (bsc#1023762)

  - CVE-2017-6074: The dccp_rcv_state_process function in net/dccp/input.c
  in the Linux kernel mishandled DCCP_PKT_REQUEST packet data structures
  in the LISTEN state, which allowed local users to cause a denial of
  service (invalid free) or possibly have unspecified other impact via an
  application that makes an IPV6_RECVPKTINFO setsockopt system call.
  (bsc#1026024).

  The following non-security bugs were fixed:

  - btrfs: fix btrfs_compat_ioctl failures on non-compat ioctls
  (bsc#1018100).

  - iwlwifi: Expose the default fallback ucode API to module info
  (boo#1021082, boo#1023884).

  - kabi: protect struct tcp_fastopen_cookie (kabi).

  - md: ensure md devices are freed before module is unloaded (bsc#1022304).

  - md: Fix a regression reported by bsc#1020048 in
  patches.fixes/0003-md-lockless-I-O-submission-for-RAID1.patch
  (bsc#982783, bsc#998106, bsc#1020048).

  - net: ethtool: Initialize buffer when querying device channel settings
  (bsc#969479 FATE#320634).

  - net: implement netif_cond_dbg macro (bsc#1019168).

  - sfc: reduce severity of PIO buffer alloc failures (bsc#1019168).

  - sfc: refactor debug-or-warnings printks (bsc#1019168).

  - xfs_dmapi: fix the debug compilation of xfs_dmapi (bsc#989056).

  - xfs: do not allow di_size with high bit set (bsc#1024234).

  - xfs: exclude never-released buffers from buftarg I/O accounting
  (bsc#1024508).

  - xfs: fix broken multi-fsb buffer logging (bsc#1024081).

  - xfs: fix buffer overflow dm_get_dirattrs/dm_get_dirattrs2 (bsc#989056).

  - xfs: fix up xfs_swap_extent_forks inline extent handling (bsc#1023888).

  - xfs: track and serialize in-flight async buffers against unmount
  (bsc#1024508).

  - xfs: track and serialize in-flight async buffers against unmount - kABI
  (bsc#1024508).");

  script_tag(name:"affected", value:"Linux Kernel on openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0541-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.49~16.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.49~16.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.49~16.2", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.49~16.1", rls:"openSUSELeap42.2"))) {
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

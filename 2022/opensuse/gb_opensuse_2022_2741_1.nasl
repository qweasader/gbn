# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854897");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1116", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-21505", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-29581", "CVE-2022-32250", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-36946");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 00:38:00 +0000 (Thu, 26 May 2022)");
  script_tag(name:"creation_date", value:"2022-08-11 01:02:49 +0000 (Thu, 11 Aug 2022)");
  script_name("openSUSE: Security Advisory for the (SUSE-SU-2022:2741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2741-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EGXCNXU52CY2RQC5VCVZFGNLQODOA5TA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the SUSE-SU-2022:2741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various
     security bugfixes.
  The following security bugs were fixed:

  - CVE-2022-36946: Fixed an incorrect packet truncation operation which
       could lead to denial of service (bnc#1201940).

  - CVE-2022-29581: Fixed improper update of reference count in net/sched
       that could cause root privilege escalation (bnc#1199665).

  - CVE-2022-20166: Fixed several possible memory safety issues due to
       unsafe operations (bsc#1200598).

  - CVE-2020-36558: Fixed a race condition involving VT_RESIZEX which could
       lead to a NULL pointer dereference and general protection fault
       (bnc#1200910).

  - CVE-2020-36557: Fixed a race condition between the VT_DISALLOCATE ioctl
       and closing/opening of TTYs that could lead to a use-after-free
       (bnc#1201429).

  - CVE-2021-33655: Fixed an out of bounds write by ioctl cmd
       FBIOPUT_VSCREENINFO (bnc#1201635).

  - CVE-2021-33656: Fixed an out of bounds write related to ioctl cmd
       PIO_FONT (bnc#1201636).

  - CVE-2022-21505: Fixed a kernel lockdown bypass via IMA policy
       (bsc#1201458).

  - CVE-2022-1462: Fixed an out-of-bounds read flaw in the TTY subsystem
       (bnc#1198829).

  - CVE-2022-1116: Fixed an integer overflow vulnerability in io_uring which
       allowed a local attacker to escalate privileges to root (bnc#1199647).-
       CVE-2022-2318: Fixed a use-after-free vulnerability in the timer handler
       in Rose subsystem that allowed unprivileged attackers to crash the
       system (bsc#1201251).

  - CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed
       multiple potential data leaks with Block and Network devices when using
       untrusted backends (bsc#1200762).
  The following non-security bugs were fixed:

  - Fixed a system crash related to the recent RETBLEED mitigation
       (bsc#1201644, bsc#1201664, bsc#1201672, bsc#1201673, bsc#1201676).

  - qla2xxx: drop patch which prevented nvme port discovery (bsc#1200651
       bsc#1200644 bsc#1201954 bsc#1201958).

  - kvm: emulate: do not adjust size of fastop and setcc subroutines
       (bsc#1201930).

  - bpf, cpumap: Remove rcpu pointer from cpu_map_build_skb signature
       (bsc#1199364).

  - bpf: enable BPF type format (BTF) (jsc#SLE-24559).

  - nfs: avoid NULL pointer dereference when there is unflushed data
       (bsc#1201196).

  - hv_netvsc: Add (more) validation for untrusted Hyper-V values
       (bsc#1199364).

  - hv_netvsc: Add comment of netvsc_xdp_xmit() (bsc#1199364).

  - hv_netvsc: Add s ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure-debuginfo", rpm:"cluster-md-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure-debuginfo", rpm:"dlm-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure-debuginfo", rpm:"gfs2-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra-debuginfo", rpm:"kernel-azure-extra-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-livepatch-devel", rpm:"kernel-azure-livepatch-devel~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional-debuginfo", rpm:"kernel-azure-optional-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure-debuginfo", rpm:"kselftests-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure-debuginfo", rpm:"ocfs2-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure-debuginfo", rpm:"reiserfs-kmp-azure-debuginfo~5.3.18~150300.38.75.1", rls:"openSUSELeap15.3"))) {
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
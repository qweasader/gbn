# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122396");
  script_cve_id("CVE-2006-6304", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272");
  script_tag(name:"creation_date", value:"2015-10-06 11:18:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T08:10:07+0000");
  script_tag(name:"last_modification", value:"2022-04-05 08:10:07 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0046");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.11.1.0.1.el5, oracleasm-2.6.18-164.11.1.0.1.el5' package(s) announced via the ELSA-2010-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.11.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change
 (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043]
 [bz 7258]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang)
 [orabug 7579314]
- FP register state is corrupted during the handling a SIGSEGV (Chuck Anderson)
 [orabug 7708133]

[2.6.18-164.11.1.el5]
- [firewire] ohci: handle receive packets with zero data (Jay Fenlason) [547241 547242] {CVE-2009-4138}
- [x86] sanity check for AMD northbridges (Andrew Jones) [549905 547518]
- [x86_64] disable vsyscall in kvm guests (Glauber Costa) [550968 542612]
- [fs] ext3: replace lock_super with explicit resize lock (Eric Sandeen) [549908 525100]
- [fs] respect flag in do_coredump (Danny Feng) [544188 544189] {CVE-2009-4036}
- [gfs2] make O_APPEND behave as expected (Steven Whitehouse) [547521 544342]
- [fs] hfs: fix a potential buffer overflow (Amerigo Wang) [540740 540741] {CVE-2009-4020}
- [fuse] prevent fuse_put_request on invalid pointer (Danny Feng) [538736 538737] {CVE-2009-4021}
- [mm] call vfs_check_frozen after unlocking the spinlock (Amerigo Wang) [548370 541956]
- [infiniband] init neigh->dgid.raw on bonding events (Doug Ledford) [543448 538067]
- [scsi] gdth: prevent negative offsets in ioctl (Amerigo Wang) [539420 539421] {CVE-2009-3080}
- [fs] gfs2: fix glock ref count issues (Steven Whitehouse) [544978 539240]
- [net] call cond_resched in rt_run_flush (Amerigo Wang) [547530 517588]
- [scsi] megaraid: fix sas permissions in sysfs (Casey Dahlin) [537312 537313] {CVE-2009-3889 CVE-2009-3939}
- [ia64] kdump: restore registers in the stack on init (Takao Indoh ) [542582 515753]
- [x86] kvm: don't ask HV for tsc khz if not using kvmclock (Glauber Costa ) [537027 531268]
- [net] sched: fix panic in bnx2_poll_work (John Feeney ) [539686 526481]
- [x86_64] fix 32-bit process register leak (Amerigo Wang ) [526797 526798]
- [cpufreq] add option to avoid smi while calibrating (Matthew Garrett ) [537343 513649]
- [kvm] use upstream kvm_get_tsc_khz (Glauber Costa ) [540896 531025]
- [net] fix unbalance rtnl locking in rt_secret_reschedule (Neil Horman ) [549907 510067]
- [net] r8169: improved rx length check errors (Neil Horman ) [552913 552438]
- [scsi] lpfc: fix FC ports offlined during target controller faults (Rob Evers ) [549906 516541]
- [net] emergency route cache flushing fixes (Thomas Graf ) [545662 545663] {CVE-2009-4272}
- [fs] fasync: split 'fasync_helper()' into separate add/remove functions (Danny Feng ) [548656 548657] {CVE-2009-4141}
- [scsi] qla2xxx: NPIV vport management pseudofiles are world writable (Tom Coughlan ) [537317 537318] {CVE-2009-3556}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.11.1.0.1.el5, oracleasm-2.6.18-164.11.1.0.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.11.1.0.1.el5", rpm:"ocfs2-2.6.18-164.11.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.11.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-164.11.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.11.1.0.1.el5debug", rpm:"ocfs2-2.6.18-164.11.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.11.1.0.1.el5xen", rpm:"ocfs2-2.6.18-164.11.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.11.1.0.1.el5", rpm:"oracleasm-2.6.18-164.11.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.11.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-164.11.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.11.1.0.1.el5debug", rpm:"oracleasm-2.6.18-164.11.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.11.1.0.1.el5xen", rpm:"oracleasm-2.6.18-164.11.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

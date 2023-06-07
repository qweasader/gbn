# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1502");
  script_cve_id("CVE-2017-18255", "CVE-2017-18270", "CVE-2017-18344", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2636", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5551", "CVE-2017-5669", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6001", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308");
  script_tag(name:"creation_date", value:"2020-01-23 11:58:09 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-02-16T10:19:47+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:19:47 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-14 18:32:00 +0000 (Tue, 14 Feb 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1502)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1502");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1502");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1502 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The perf_cpu_time_max_percent_handler function in kernel/events/core.c in the Linux kernel before 4.11 allows local users to cause a denial of service (integer overflow) or possibly have unspecified other impact via a large value, as demonstrated by an incorrect sample-rate calculation.(CVE-2017-18255)

In the Linux kernel before 4.13.5, a local user could create keyrings for other users via keyctl commands, setting unwanted defaults or causing a denial of service.(CVE-2017-18270)

The timer_create syscall implementation in kernel/time/posix-timers.c in the Linux kernel doesn't properly validate the sigevent->sigev_notify field, which leads to out-of-bounds access in the show_timer function.(CVE-2017-18344)

arch/x86/kvm/emulate.c in the Linux kernel through 4.9.3 allows local users to obtain sensitive information from kernel memory or cause a denial of service (use-after-free) via a crafted application that leverages instruction emulation for fxrstor, fxsave, sgdt, and sidt.(CVE-2017-2584)

Linux kernel built with the KVM visualization support (CONFIG_KVM), with nested visualization(nVMX) feature enabled(nested=1), is vulnerable to host memory leakage issue. It could occur while emulating VMXON instruction in 'handle_vmon'. An L1 guest user could use this flaw to leak host memory potentially resulting in DoS.(CVE-2017-2596)

A race condition flaw was found in the N_HLDC Linux kernel driver when accessing n_hdlc.tbuf list that can lead to double free. A local, unprivileged user able to set the HDLC line discipline on the tty device could use this flaw to increase their privileges on the system.(CVE-2017-2636)

A flaw was found that can be triggered in keyring_search_iterator in keyring.c if type->match is NULL. A local user could use this flaw to crash the system or, potentially, escalate their privileges.(CVE-2017-2647)

A race condition leading to a NULL pointer dereference was found in the Linux kernel's Link Layer Control implementation. A local attacker with access to ping sockets could use this flaw to crash the system.(CVE-2017-2671)

A vulnerability was found in the Linux kernel in 'tmpfs' file system. When file permissions are modified via 'chmod' and the user is not in the owning group or capable of CAP_FSETID, the setgid bit is cleared in inode_change_ok(). Setting a POSIX ACL via 'setxattr' sets the file permissions as well as the new ACL, but doesn't clear the setgid bit in a similar way, this allows to bypass the check in 'chmod'.(CVE-2017-5551)

The do_shmat function in ipc/shm.c in the Linux kernel, through 4.9.12, does not restrict the address calculated by a certain rounding operation. This allows privileged local users to map page zero and, consequently, bypass a protection mechanism that exists for the mmap system call. This is possible by making crafted shmget and shmat system calls in a privileged context.(CVE-2017-5669)

A vulnerability was found ... [Please see the references for more information on the vulnerabilities]");

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

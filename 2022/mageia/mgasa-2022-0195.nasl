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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0195");
  script_cve_id("CVE-2022-0500", "CVE-2022-1012", "CVE-2022-1734", "CVE-2022-23222", "CVE-2022-28893", "CVE-2022-29581");
  script_tag(name:"creation_date", value:"2022-05-23 04:32:41 +0000 (Mon, 23 May 2022)");
  script_version("2022-10-03T10:13:16+0000");
  script_tag(name:"last_modification", value:"2022-10-03 10:13:16 +0000 (Mon, 03 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:00 +0000 (Fri, 30 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0195");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0195.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30436");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.36");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.37");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.38");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.39");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.40");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.41");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.41 and fixes at least the
following security issues:

A flaw was found in unrestricted eBPF usage by the BPF_BTF_LOAD, leading
to a possible out-of-bounds memory write in the Linux kernel BPF subsystem
due to the way a user loads BTF. This flaw allows a local user to crash or
escalate their privileges on the system. NOTE: Mageia kernels by default
prevents unprivileged users from being able to use eBPF so this would
require a privileged user with CAP_SYS_ADMIN or root to be able to abuse
this flaw reducing its attack space (CVE-2022-0500).

Due to the small table perturb size, a memory leak flaw was found in the
Linux kernel's TCP source port generation algorithm in the net/ipv4/tcp.c
function. This flaw allows an attacker to leak information and may cause
a denial of service (CVE-2022-1012).

A flaw was found in the Linux kernel's nfcmrvl_nci_unregister_dev()
function. A race condition leads to a use-after-free issue when simulating
the NFC device from the user space (CVE-2022-1734).

A flaw was found in the Linux kernel's adjust_ptr_min_max_vals in the
kernel/bpf/verifier.c function. In this flaw, a missing sanity check for
*_OR_NULL pointer types that perform pointer arithmetic may cause a kernel
information leak issue. NOTE: Mageia kernels by default prevents
unprivileged users from being able to use eBPF so this would require a
privileged user with CAP_SYS_ADMIN or root to be able to abuse this flaw
reducing its attack space (CVE-2022-23222).

The SUNRPC subsystem in the Linux kernel through 5.17.2 can call
xs_xprt_free before ensuring that sockets are in the intended state
(CVE-2022-28893).

Improper Update of Reference Count vulnerability in net/sched of Linux
Kernel allows local attacker to cause privilege escalation to root
(CVE-2022-29581).

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.41-1.mga8", rpm:"kernel-linus-5.15.41-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.41~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.41-1.mga8", rpm:"kernel-linus-devel-5.15.41-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.41~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.41~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.41~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.41-1.mga8", rpm:"kernel-linus-source-5.15.41-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.41~1.mga8", rls:"MAGEIA8"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0100");
  script_cve_id("CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0742", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-23960");
  script_tag(name:"creation_date", value:"2022-03-15 04:07:12 +0000 (Tue, 15 Mar 2022)");
  script_version("2022-03-28T04:06:51+0000");
  script_tag(name:"last_modification", value:"2022-03-28 04:06:51 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-25 19:02:00 +0000 (Fri, 25 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0100)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0100");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0100.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30157");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00598.html");
  script_xref(name:"URL", value:"https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability/spectre-bhb");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2022/q1/173");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.26");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.27");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.28");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2022-0100 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.28 and fixes at least the
following security issues:

Non-transparent sharing of branch predictor selectors between contexts
in some Intel(R) Processors may allow an authorized user to potentially
enable information disclosure via local access (CVE-2022-0001).

Non-transparent sharing of branch predictor within a context in some
Intel(R) Processors may allow an authorized user to potentially enable
information disclosure via local access (CVE-2022-0002).

A memory leak flaw was found in the Linux kernel's ICMPv6 networking
protocol, in the way a user generated malicious ICMPv6 packets. This
flaw allows a remote user to crash the system (CVE-2022-0742).

Several Linux PV device frontends are using the grant table interfaces
for removing access rights of the backends in ways being subject to
race conditions, resulting in potential data leaks, data corruption
by malicious backends, and denial of service triggered by malicious
backends:

blkfront, netfront, scsifront and the gntalloc driver are testing
whether a grant reference is still in use. If this is not the case,
they assume that a following removal of the granted access will always
succeed, which is not true in case the backend has mapped the granted
page between those two operations. As a result the backend can keep
access to the memory page of the guest no matter how the page will be
used after the frontend I/O has finished. The xenbus driver has a
similar problem, as it doesn't check the success of removing the
granted access of a shared ring buffer (blkfront: CVE-2022-23036,
netfront: CVE-2022-23037, scsifront: CVE-2022-23038,
gntalloc: CVE-2022-23039, xenbus: CVE-2022-23040)

blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront,
and pvcalls are using a functionality to delay freeing a grant reference
until it is no longer in use, but the freeing of the related data page
is not synchronized with dropping the granted access. As a result the
backend can keep access to the memory page even after it has been freed
and then re-used for a different purpose (CVE-2022-23041).

netfront will fail a BUG_ON() assertion if it fails to revoke access in
the rx path. This will result in a Denial of Service (DoS) situation of
the guest which can be triggered by the backend (CVE-2022-23042).

Certain Arm Cortex and Neoverse processors through 2022-03-08 do not
properly restrict cache speculation, aka Spectre-BHB. An attacker can
leverage the shared branch history in the Branch History Buffer (BHB)
to influence mispredicted branches. Then, cache allocation can allow
the attacker to obtain sensitive information (CVE-2022-23960).

It was found that the default LFENCE-based Spectre v2 mitigation on
AMD cpus is insufficient to mitigate such attacks. Because of that,
the code have been switched to use generic retpolines on AMD cpus
by default.

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.28-1.mga8", rpm:"kernel-desktop-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.28-1.mga8", rpm:"kernel-desktop-devel-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.28-1.mga8", rpm:"kernel-desktop586-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.28-1.mga8", rpm:"kernel-desktop586-devel-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.28-1.mga8", rpm:"kernel-server-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.28-1.mga8", rpm:"kernel-server-devel-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.28-1.mga8", rpm:"kernel-source-5.15.28-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.32~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.28~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.28-desktop-1.mga8", rpm:"virtualbox-kernel-5.15.28-desktop-1.mga8~6.1.32~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.28-server-1.mga8", rpm:"virtualbox-kernel-5.15.28-server-1.mga8~6.1.32~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.32~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.32~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.28-desktop-1.mga8", rpm:"xtables-addons-kernel-5.15.28-desktop-1.mga8~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.28-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.15.28-desktop586-1.mga8~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.28-server-1.mga8", rpm:"xtables-addons-kernel-5.15.28-server-1.mga8~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.18~1.58.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.18~1.58.mga8", rls:"MAGEIA8"))) {
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

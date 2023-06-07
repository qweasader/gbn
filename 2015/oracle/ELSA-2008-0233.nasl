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
  script_oid("1.3.6.1.4.1.25623.1.0.122593");
  script_cve_id("CVE-2007-5498", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1619", "CVE-2008-1669");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:47 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-04-05 03:03:58 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2008-0233)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0233");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0233.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-53.1.19.0.1.el5, oracleasm-2.6.18-53.1.19.0.1.el5' package(s) announced via the ELSA-2008-0233 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-53.1.19.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [ORA 6045759]
- [NET] Fix msi issue with kexec/kdump (Michael Chan) [ORA 6219364]
- [MM] Fix alloc_pages_node() static nid' race made kernel crash (Joe Jin) [ORA 6187457]
- [splice] Fix bad unlock_page() in error case (Jens Axboe) [ORA 6263574]
- [dio] fix error-path crashes (Linux Torvalds) [ORA 6242289]

[2.6.18-53.1.19.el5]
- [xen] check num of segments in block backend driver (Bill Burns ) [378281]
- [x86_64] update IO-APIC dest field to 8-bit for xAPIC (Dave Anderson ) [442922]
- Update: [fs] fix race condition in dnotify (Alexander Viro ) [439758] {CVE-2008-1375}
- Update: [xen] ia64: ftp stress test fixes between HVM/Dom0 (Tetsu Yamamoto ) [427400] {CVE-2008-1619}

[2.6.18-53.1.18.el5]
- Update: [fs] fix race condition in dnotify (Alexander Viro ) [439758] {CVE-2008-1375}

[2.6.18-53.1.17.el5]
- [fs] fix race condition in dnotify (Alexander Viro ) [439758] {CVE-2008-1375}
- [pci] hotplug: PCI Express problems with bad DLLPs (Kei Tokunaga ) [440438]
- [nfs] stop sillyrenames and unmounts from racing (Steve Dickson ) [440447]
- [x86] clear df flag for signal handlers (Jason Baron ) [437316] {CVE-2008-1367}
- [xen] ia64: ftp stress test fixes between HVM/Dom0 (Tetsu Yamamoto ) [427400] {CVE-2008-1619}
- [xen] ia64: fix ssm_i emulation barrier and vdso pv (Tetsu Yamamoto ) [427400] {CVE-2008-1619}

[2.6.18-53.1.16.el5]
- [misc] fix range check in fault handlers with mremap (Vitaly Mayatskikh ) [428970]
- [video] neofb: avoid overwriting fb_info fields (Anton Arapov ) [430253]

[2.6.18-53.1.15.el5]
- [libata] sata_nv: un-blacklist hitachi drives (David Milburn ) [433617]
- [libata] sata_nv: may send cmds with duplicate tags (David Milburn ) [433617]
- [s390] qdio: output queue stall on FCP and net devs (Hans-Joachim Picht ) [412071]
- [xen] ia64: guest has bad network performance (Tetsu Yamamoto ) [433616]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-53.1.19.0.1.el5, oracleasm-2.6.18-53.1.19.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~53.1.19.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.19.0.1.el5", rpm:"ocfs2-2.6.18-53.1.19.0.1.el5~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.19.0.1.el5PAE", rpm:"ocfs2-2.6.18-53.1.19.0.1.el5PAE~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.19.0.1.el5debug", rpm:"ocfs2-2.6.18-53.1.19.0.1.el5debug~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-53.1.19.0.1.el5xen", rpm:"ocfs2-2.6.18-53.1.19.0.1.el5xen~1.2.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.19.0.1.el5", rpm:"oracleasm-2.6.18-53.1.19.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.19.0.1.el5PAE", rpm:"oracleasm-2.6.18-53.1.19.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.19.0.1.el5debug", rpm:"oracleasm-2.6.18-53.1.19.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-53.1.19.0.1.el5xen", rpm:"oracleasm-2.6.18-53.1.19.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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

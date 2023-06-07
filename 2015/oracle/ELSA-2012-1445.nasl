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
  script_oid("1.3.6.1.4.1.25623.1.0.123782");
  script_cve_id("CVE-2012-2100");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:29 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-04-05 03:03:58 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1445)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1445");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1445.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.20.1.el5, oracleasm-2.6.18-308.20.1.el5' package(s) announced via the ELSA-2012-1445 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-308.20.1.el5]
- Revert: [x86] mm: randomize SHLIB_BASE (Dave Anderson) [804953 804954] {CVE-2012-1568}

[2.6.18-308.19.1.el5]
- [net] be2net: Remove code that stops further access to BE NIC based on UE bits (Alexander Gordeev) [867896 862811]
- [net] netpoll: fix an incorrect check for NULL pointer (Alexander Gordeev) [856079 848098]
- [net] mlx4: Add support for EEH error recovery (Alexander Gordeev) [847404 798048]
- [fs] ext4: fix undefined bit shift result in ext4_fill_flex_info (Eric Sandeen) [809688 809689] {CVE-2012-2100}
- [fs] ext4: fix undefined behavior in ext4_fill_flex_info (Eric Sandeen) [809688 809689] {CVE-2012-2100}
- [fs] fix crash if block {device<pipe>size} read & changed at sametime (Mikulas Patocka) [864823 756506]
- [x86] mm: randomize SHLIB_BASE (Dave Anderson) [804953 804954] {CVE-2012-1568}
- [net] ipv6: Fix fib6_dump_table walker leak (Jiri Benc) [861387 819830]
- [fs] cifs: update cifs_dfs_d_automount caller path (Sachin Prabhu) [858774 857448]
- [xen] x86: change the default behaviour of CVE-2012-2934 fix (Petr Matousek) [859946 858724]
- [net] ipvs: allow transmit of GRO aggregated skbs (Jesper Brouer) [857966 854067]
- [scsi] isci: fixup linkspeed definitions (David Milburn) [854986 833000]
- [fs] nfs: nfs_d_automount update caller path after do_add_mount (Carlos Maiolino) [857552 834379]
- [fs] vfs: Fix vfsmount overput on simultaneous automount (Carlos Maiolino) [857552 834379]

[2.6.18-308.18.1.el5]
- [fs] autofs4: Merge the remaining dentry ops tables (Ian Kent) [857558 850977]

[2.6.18-308.17.1.el5]
- [fs] cifs: Invalidate file cache in case of posix open (Sachin Prabhu) [857964 852526]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.20.1.el5, oracleasm-2.6.18-308.20.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.20.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.20.1.el5", rpm:"ocfs2-2.6.18-308.20.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.20.1.el5PAE", rpm:"ocfs2-2.6.18-308.20.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.20.1.el5debug", rpm:"ocfs2-2.6.18-308.20.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.20.1.el5xen", rpm:"ocfs2-2.6.18-308.20.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.20.1.el5", rpm:"oracleasm-2.6.18-308.20.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.20.1.el5PAE", rpm:"oracleasm-2.6.18-308.20.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.20.1.el5debug", rpm:"oracleasm-2.6.18-308.20.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.20.1.el5xen", rpm:"oracleasm-2.6.18-308.20.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

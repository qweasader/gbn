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
  script_oid("1.3.6.1.4.1.25623.1.0.123913");
  script_cve_id("CVE-2012-2136");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:13 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-04T14:03:28+0000");
  script_tag(name:"last_modification", value:"2022-04-04 14:03:28 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0690-1");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0690-1.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.8.1.0.1.el5, oracleasm-2.6.18-308.8.1.0.1.el5' package(s) announced via the ELSA-2012-0690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-308.8.1.0.1.el5]
- [net] bonding: fix carrier detect when bond is down [orabug 12377284]
- [mm] fix hugetlb page leak (Dave McCracken) [orabug 12375075]
- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)
- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)
- [x86] Fix lvt0 reset when hvm boot up with noapic param
- [scsi] remove printk's when doing I/O to a dead device (John Sobecki, Chris Mason)
 [orabug 12342275]
- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]
- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]
- [net] net: Redo the broken redhat netconsole over bonding (Tina Yang) [orabug 12740042]
- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]
- [scsi] fix scsi hotplug and rescan race [orabug 10260172]
- fix filp_close() race (Joe Jin) [orabug 10335998]
- make xenkbd.abs_pointer=1 by default [orabug 67188919]
- [xen] check to see if hypervisor supports memory reservation change
 (Chuck Anderson) [orabug 7556514]
- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki)
 [orabug 10315433]
- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]
- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105]
 RDS: Fix BUG_ONs to not fire when in a tasklet
 ipoib: Fix lockup of the tx queue
 RDS: Do not call set_page_dirty() with irqs off (Sherman Pun)
 RDS: Properly unmap when getting a remote access error (Tina Yang)
 RDS: Fix locking in rds_send_drop_to()
- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson)
 [orabug 9107465]
- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson)
 [orabug 9764220]
- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]
- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro,
 Guru Anbalagane) [orabug 6124033]
- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]
- [ib] fix memory corruption (Andy Grover) [orabug 9972346]

[2.6.18-308.8.1.el5]
- [net] sock: validate data_len before allocating skb in sock_alloc_send_pskb() (Jason Wang) [816290 816106] {CVE-2012-2136}
- [net] tg3: Fix VLAN tagging assignments (John Feeney) [817691 797011]
- [net] ixgbe: do not stop stripping VLAN tags in promiscuous mode (Andy Gospodarek) [809791 804800]
- [s390] zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl (Hendrik Brueckner) [810123 808489]
- [x86] unwind information fix for the vsyscall DSO (Prarit Bhargava) [807930 805799]

[2.6.18-308.7.1.el5]
- [fs] epoll: Don't limit non-nested epoll paths (Jason Baron) [809380 804778]

[2.6.18-308.6.1.el5]
- [scsi] fc class: fix scanning when devs are offline (Mike Christie) [816684 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.8.1.0.1.el5, oracleasm-2.6.18-308.8.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.0.1.el5", rpm:"ocfs2-2.6.18-308.8.1.0.1.el5~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-308.8.1.0.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.0.1.el5debug", rpm:"ocfs2-2.6.18-308.8.1.0.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.8.1.0.1.el5xen", rpm:"ocfs2-2.6.18-308.8.1.0.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.0.1.el5", rpm:"oracleasm-2.6.18-308.8.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-308.8.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.0.1.el5debug", rpm:"oracleasm-2.6.18-308.8.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.8.1.0.1.el5xen", rpm:"oracleasm-2.6.18-308.8.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

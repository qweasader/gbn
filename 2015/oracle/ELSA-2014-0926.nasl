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
  script_oid("1.3.6.1.4.1.25623.1.0.123351");
  script_cve_id("CVE-2014-2678", "CVE-2014-4021");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:38 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-04-05 03:03:58 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0926)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0926");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0926.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-371.11.1.el5, oracleasm-2.6.18-371.11.1.el5' package(s) announced via the ELSA-2014-0926 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-371.11.1]
- [fs] dcache: fix cleanup on warning in d_splice_alias (Denys Vlasenko) [1109720 1080606]
- [net] neigh: Make neigh_add_timer symmetrical to neigh_del_timer (Marcelo Ricardo Leitner) [1111195 1109888]
- [net] neigh: set NUD_INCOMPLETE when probing router reachability (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: router reachability probing (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: probe routes asynchronous in rt6_probe (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ndisc: Update neigh->updated with write lock (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: remove the unnecessary statement in find_match() (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: fix route selection if CONFIG_IPV6_ROUTER_PREF unset (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: Fix def route failover when CONFIG_IPV6_ROUTER_PREF=n (Marcelo Ricardo Leitner) [1106354 1090806]
- [net] ipv6: Prefer reachable nexthop only if the caller requests (Marcelo Ricardo Leitner) [1106354 1090806]
- [fs] ext4/jbd2: don't wait forever stale tid caused by wraparound (Eric Sandeen) [1097528 980268]
- [fs] ext4: Initialize fsync transaction ids in ext4_new_inode() (Eric Sandeen) [1097528 980268]
- [fs] jbd2: don't wake kjournald unnecessarily (Eric Sandeen) [1097528 980268]
- [fs] jbd2: fix fsync() tid wraparound bug (Eric Sandeen) [1097528 980268]
- [infiniband] rds: do not deref NULL dev in rds_iw_laddr_check() (Jacob Tanenbaum) [1093311 1093312] {CVE-2014-2678}
- [fs] nfs4: Add recovery for individual stateids - partial backport. (Dave Wysochanski) [1113468 867570]
- [fs] nfs4: Don't start state recovery in nfs4_close_done - clean backport. (Dave Wysochanski) [1113468 867570]
- [xen] page-alloc: scrub anonymous domain heap pages upon freeing (Vitaly Kuznetsov) [1103648 1103649] {CVE-2014-4021}

[2.6.18-371.10.1]
- [net] ipv6: fix overlap check for fragments (Francesco Fusco) [1107932 995277]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-371.11.1.el5, oracleasm-2.6.18-371.11.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.11.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.11.1.el5", rpm:"ocfs2-2.6.18-371.11.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.11.1.el5PAE", rpm:"ocfs2-2.6.18-371.11.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.11.1.el5debug", rpm:"ocfs2-2.6.18-371.11.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.11.1.el5xen", rpm:"ocfs2-2.6.18-371.11.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.11.1.el5", rpm:"oracleasm-2.6.18-371.11.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.11.1.el5PAE", rpm:"oracleasm-2.6.18-371.11.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.11.1.el5debug", rpm:"oracleasm-2.6.18-371.11.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.11.1.el5xen", rpm:"oracleasm-2.6.18-371.11.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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

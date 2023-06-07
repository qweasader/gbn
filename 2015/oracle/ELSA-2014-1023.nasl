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
  script_oid("1.3.6.1.4.1.25623.1.0.123341");
  script_cve_id("CVE-2014-0181", "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2706", "CVE-2014-3534", "CVE-2014-4667");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:30 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T06:57:19+0000");
  script_tag(name:"last_modification", value:"2022-04-05 06:57:19 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-1023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1023");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.6.3]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.6.3]
- [net] l2tp_ppp: fail when socket option level is not SOL_PPPOL2TP (Petr Matousek) [1119465 1119466] {CVE-2014-4943}

[3.10.0-123.6.2.el7]
- [s390] ptrace: correct insufficient sanitization when setting psw mask (Hendrik Brueckner) [1114090 1113673]

[3.10.0-123.6.1.el7]
- [x86] ptrace: force IRET path after a ptrace_stop() (Oleg Nesterov) [1115934 1115935] {CVE-2014-4699}

[3.10.0-123.5.1.el7]
- [net] ipv4/tunnels: fix an oops when using ipip/sit with IPsec (Jiri Pirko) [1114957 1108857]
- [scsi] Add timeout to avoid infinite command retry (Ewan Milne) [1114468 1061871]
- [net] filter: let bpf_tell_extensions return SKF_AD_MAX (Jiri Benc) [1114404 1079524]
- [net] filter: introduce SO_BPF_EXTENSIONS (Jiri Benc) [1114404 1079524]
- [net] sctp: Fix sk_ack_backlog wrap-around problem (Daniel Borkmann) [1113971 1112726] {CVE-2014-4667}
- [tty] Set correct tty name in 'active' sysfs attribute (Denys Vlasenko) [1113467 1066403]
- [powerpc] tm: Disable IRQ in tm_recheckpoint (Larry Woodman) [1113150 1088224]
- [scsi] qla2xxx: Update version number to 8.06.00.08.07.0-k3 (Chad Dupuis) [1112389 1090378]
- [scsi] qla2xxx: Reduce the time we wait for a command to complete during SCSI error handling (Chad Dupuis) [11123
89 1090378]
- [scsi] qla2xxx: Clear loop_id for ports that are marked lost during fabric scanning (Chad Dupuis) [1112389 109037
8]
- [scsi] qla2xxx: Avoid escalating the SCSI error handler if the command is not found in firmware (Chad Dupuis) [11
12389 1090378]
- [scsi] qla2xxx: Don't check for firmware hung during the reset context for ISP82XX (Chad Dupuis) [1112389 1090378
]
- [scsi] qla2xxx: Issue abort command for outstanding commands during cleanup when only firmware is alive (Chad Dup
uis) [1112389 1090378]
- [fs] nfs: Apply NFS_MOUNT_CMP_FLAGMASK to nfs_compare_remount_data() (Scott Mayhew) [1109407 1103805]
- [ethernet] bnx2x: Fix kernel crash and data miscompare after EEH recovery (Michal Schmidt) [1107721 1101808]
- [net] gro: restore frag0 optimization (and fix crash) (Michal Schmidt) [1099950 1069741]
- [watchdog] hpwdt: display informative string (Nigel Croxon) [1096961 1074038]
- [net] Use netlink_ns_capable to verify the permissions of netlink messages (Jiri Benc) [1094271 1094272] {CVE-2014
-0181}
- [net] netlink: Add variants of capable for use on netlink messages (Jiri Benc) [1094271 1094272] {CVE-2014-0181}
- [net] diag: Move the permission check in sock_diag_put_filterinfo to packet_diag_dump (Jiri Benc) [1094271 109427
2] {CVE-2014-0181}
- [net] netlink: Rename netlink_capable netlink_allowed (Jiri Benc) [1094271 1094272] {CVE-2014-0181}
- [net] diag: Fix ns_capable check in sock_diag_put_filterinfo (Jiri Benc) [1094271 1094272] {CVE-2014-0181}
- [net] netlink: Fix permission check in netlink_connect() (Jiri Benc) [1094271 1094272] {CVE-2014-0181}
- [kernel] cputime: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.6.3.el7", rls:"OracleLinux7"))) {
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

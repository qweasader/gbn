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
  script_oid("1.3.6.1.4.1.25623.1.0.122052");
  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-3593", "CVE-2011-4326");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-1465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1465");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1465.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-1465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.21.1.el6]
- [net] ipv6/udp: fix the wrong headroom check (Thomas Graf) [753167 698170]

[2.6.32-131.20.1.el6]
- [net] vlan: fix panic when handling priority tagged frames (Andy Gospodarek) [742849 714936] {CVE-2011-3593}
- [netdrv] igb: fix WOL on second port of i350 device (Frantisek Hrbata) [743807 718293]
- [kernel] fix taskstats io infoleak (Jerome Marchand) [716847 716848] {CVE-2011-2494}
- [tpm] Zero buffer after copying to userspace (Jiri Benc) [732632 732633] {CVE-2011-1162}
- [scsi] Revert megaraid_sas: Driver only report tape drive, JBOD and logic drives (Tomas Henzl) [741167 736667]
- [x86] acpi: Prevent acpiphp from deadlocking on PCI-to-PCI bridge remove (Prarit Bhargava) [745557 732706]
- [net] sctp: deal with multiple COOKIE_ECHO chunks (Frantisek Hrbata) [743510 729220]
- [scsi] iscsi_tcp: fix locking around iscsi sk user data (Mike Christie) [741704 647268]
- [kernel] first time swap use results in heavy swapping (Hendrik Brueckner) [747868 722461]
- [scsi] Reduce error recovery time by reducing use of TURs (Mike Christie) [744811 691945]
- [fs] cifs: add fallback in is_path_accessible for old servers (Jeff Layton) [738301 692709] {CVE-2011-3363}
- [fs] cifs: always do is_path_accessible check in cifs_mount (Jeff Layton) [738301 692709] {CVE-2011-3363}
- [net] ipv6: fix NULL dereference in udp6_ufo_fragment() (Jason Wang) [748808 740465]
- [net] ipv6: make fragment identifications less predictable (Jiri Pirko) [723432 723433] {CVE-2011-2699}

[2.6.32-131.19.1.el6]
- [scsi] scan: don't fail scans when host is in recovery (Mike Christie) [734774 713682]
- [netdrv] b43: allocate receive buffers big enough for max frame len + offset (RuiRui Yang) [738204 738205] {CVE-2011-3359}
- [fs] fuse: check size of FUSE_NOTIFY_INVAL_ENTRY message (RuiRui Yang) [736764 736765] {CVE-2011-3353}
- [fs] cifs: fix possible memory corruption in CIFSFindNext (Jeff Layton) [737482 730354] {CVE-2011-3191}
- [kernel] perf tools: do not look at ./config for configuration (Jiri Benc) [730203 730204] {CVE-2011-2905}
- [x86] mm: Fix pgd_lock deadlock (Andrew Jones) [737570 691310]
- [mm] pdpte registers are not flushed when PGD entry is changed in x86 PAE mode (Andrew Jones) [737570 691310]
- [mm] Revert 'fix pgd_lock deadlock' (Andrew Jones) [737570 691310]
- [fs] corrupted GUID partition tables can cause kernel oops (Jerome Marchand) [695981 695982] {CVE-2011-1577}
- [net] Compute protocol sequence numbers and fragment IDs using MD5. (Jiri Pirko) [732664 732665] {CVE-2011-3188}
- [crypto] Move md5_transform to lib/md5.c (Jiri Pirko) [732664 732665] {CVE-2011-3188}
- [fs] SUNRPC: Fix use of static variable in rpcb_getport_async (Steve Dickson) [740230 723650]
- [fs] NFSv4.1: update nfs4_fattr_bitmap_maxsz (Steve Dickson) [740230 723650]
- [fs] SUNRPC: Fix a race between work-queue and rpc_killall_tasks (Steve Dickson) [740230 723650]
- [fs] SUNRPC: Ensure we always run ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.21.1.el6", rls:"OracleLinux6"))) {
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

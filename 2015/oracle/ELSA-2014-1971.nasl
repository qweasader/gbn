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
  script_oid("1.3.6.1.4.1.25623.1.0.123230");
  script_cve_id("CVE-2013-2929", "CVE-2014-1739", "CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3631", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-4027", "CVE-2014-4652", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-5045", "CVE-2014-6410");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:01 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-01-12T14:05:07+0000");
  script_tag(name:"last_modification", value:"2022-01-12 14:05:07 +0000 (Wed, 12 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 13:29:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-1971)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1971");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1971.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1971 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.13.1]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.13.1]
- [powerpc] mm: Make sure a local_irq_disable prevent a parallel THP split (Don Zickus) [1151057 1083296]
- [powerpc] Implement __get_user_pages_fast() (Don Zickus) [1151057 1083296]
- [scsi] vmw_pvscsi: Some improvements in pvscsi driver (Ewan Milne) [1144016 1075090]
- [scsi] vmw_pvscsi: Add support for I/O requests coalescing (Ewan Milne) [1144016 1075090]
- [scsi] vmw_pvscsi: Fix pvscsi_abort() function (Ewan Milne) [1144016 1075090]

[3.10.0-123.12.1]
- [alsa] control: Make sure that id->index does not overflow (Jaroslav Kysela) [1117313 1117314] {CVE-2014-4656}
- [alsa] control: Handle numid overflow (Jaroslav Kysela) [1117313 1117314] {CVE-2014-4656}
- [alsa] control: Protect user controls against concurrent access (Jaroslav Kysela) [1117338 1117339] {CVE-2014-4652}
- [alsa] control: Fix replacing user controls (Jaroslav Kysela) [1117323 1117324] {CVE-2014-4654 CVE-2014-4655}
- [net] sctp: fix remote memory pressure from excessive queueing (Daniel Borkmann) [1155750 1152755] {CVE-2014-3688}
- [net] sctp: fix panic on duplicate ASCONF chunks (Daniel Borkmann) [1155737 1152755] {CVE-2014-3687}
- [net] sctp: fix skb_over_panic when receiving malformed ASCONF chunks (Daniel Borkmann) [1147856 1152755] {CVE-2014-3673}
- [net] sctp: handle association restarts when the socket is closed (Daniel Borkmann) [1147856 1152755] [1155737 1152755] [1155750 1152755]
- [pci] Add ACS quirk for Intel 10G NICs (Alex Williamson) [1156447 1141399]
- [pci] Add ACS quirk for Solarflare SFC9120 & SFC9140 (Alex Williamson) [1158316 1131552]
- [lib] assoc_array: Fix termination condition in assoc array garbage collection (David Howells) [1155136 1139431] {CVE-2014-3631}
- [block] cfq-iosched: Add comments on update timing of weight (Vivek Goyal) [1152874 1116126]
- [block] cfq-iosched: Fix wrong children_weight calculation (Vivek Goyal) [1152874 1116126]
- [powerpc] mm: Check paca psize is up to date for huge mappings (Gustavo Duarte) [1151927 1107337]
- [x86] perf/intel: ignore CondChgd bit to avoid false NMI handling (Don Zickus) [1146819 1110264]
- [x86] smpboot: initialize secondary CPU only if master CPU will wait for it (Phillip Lougher) [1144295 968147]
- [x86] smpboot: Log error on secondary CPU wakeup failure at ERR level (Igor Mammedov) [1144295 968147]
- [x86] smpboot: Fix list/memory corruption on CPU hotplug (Igor Mammedov) [1144295 968147]
- [acpi] processor: do not mark present at boot but not onlined CPU as onlined (Igor Mammedov) [1144295 968147]
- [fs] udf: Avoid infinite loop when processing indirect ICBs (Jacob Tanenbaum) [1142321 1142322] {CVE-2014-6410}
- [hid] picolcd: fix memory corruption via OOB write (Jacob Tanenbaum) [1141408 1141409] {CVE-2014-3186}
- [usb] serial/whiteheat: fix memory corruption flaw (Jacob Tanenbaum) [1141403 1141404] {CVE-2014-3185}
- [hid] fix off by one error ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.13.1.el7", rls:"OracleLinux7"))) {
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

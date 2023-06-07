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
  script_oid("1.3.6.1.4.1.25623.1.0.123124");
  script_cve_id("CVE-2014-3215", "CVE-2014-8171", "CVE-2014-9529", "CVE-2014-9584");
  script_tag(name:"creation_date", value:"2015-10-06 06:48:11 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:50:33+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:50:33 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-3032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3032");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-68.1.3.el6uek, dtrace-modules-3.8.13-68.1.3.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-68.1.3]
- isofs: Fix unchecked printing of ER records (Jan Kara) [Orabug: 20930551] {CVE-2014-9584}
- KEYS: close race between key lookup and freeing (Sasha Levin) [Orabug: 20930548] {CVE-2014-9529} {CVE-2014-9529}
- mm: memcg: do not allow task about to OOM kill to bypass the limit (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- mm: memcg: do not declare OOM from __GFP_NOFAIL allocations (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- fs: buffer: move allocation failure loop into the allocator (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- mm: memcg: handle non-error OOM situations more gracefully (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- mm: memcg: do not trap chargers with full callstack on OOM (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- mm: memcg: rework and document OOM waiting and wakeup (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- mm: memcg: enable memcg OOM killer only for user faults (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- x86: finish user fault error path with fatal signal (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- arch: mm: pass userspace fault flag to generic fault handler (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}
- selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID. (Stephen Smalley) [Orabug: 20930501] {CVE-2014-3215}");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-68.1.3.el6uek, dtrace-modules-3.8.13-68.1.3.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.1.3.el6uek", rpm:"dtrace-modules-3.8.13-68.1.3.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.1.3.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-68.1.3.el7uek", rpm:"dtrace-modules-3.8.13-68.1.3.el7uek~0.4.3~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.1.3.el7uek", rls:"OracleLinux7"))) {
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

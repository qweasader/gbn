# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122821");
  script_cve_id("CVE-2013-7421", "CVE-2014-9644", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2016-01-11 09:11:57 +0000 (Mon, 11 Jan 2016)");
  script_version("2022-04-04T14:03:28+0000");
  script_tag(name:"last_modification", value:"2022-04-04 14:03:28 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2016-3503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-3503");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-3503.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-400.37.15.el5uek, mlnx_en-2.6.32-400.37.15.el6uek, ofa-2.6.32-400.37.15.el5uek, ofa-2.6.32-400.37.15.el6uek' package(s) announced via the ELSA-2016-3503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[2.6.32-400.37.15uek]
- ipc/sem.c: fully initialize sem_array before making it visible (Manfred Spraul) [Orabug: 22250043] {CVE-2015-7613}
- Initialize msg/shm IPC objects before doing ipc_addid() (Linus Torvalds) [Orabug: 22250043] {CVE-2015-7613}
- crypto: add missing crypto module aliases (Mathias Krause) [Orabug: 22249655] {CVE-2013-7421} {CVE-2014-9644}
- crypto: include crypto- module prefix in template (Kees Cook) [Orabug: 22249655] {CVE-2013-7421} {CVE-2014-9644}
- crypto: prefix module autoloading with 'crypto-' (Kees Cook) [Orabug: 22249655] {CVE-2013-7421} {CVE-2014-9644}

[2.6.32-400.37.14uek]
- KVM: add arg to ac_interception() missing from 'KVM: x86: work around infinite loop in microcode when #AC is delivered' (Chuck Anderson) [Orabug: 22336493] {CVE-2015-5307}

[2.6.32-400.37.13uek]
- KVM: svm: unconditionally intercept #DB (Paolo Bonzini) [Orabug: 22336518] {CVE-2015-8104} {CVE-2015-8104}
- KVM: x86: work around infinite loop in microcode when #AC is delivered (Eric Northup) [Orabug: 22336493] {CVE-2015-5307} {CVE-2015-5307}");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-400.37.15.el5uek, mlnx_en-2.6.32-400.37.15.el6uek, ofa-2.6.32-400.37.15.el5uek, ofa-2.6.32-400.37.15.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.37.15.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.37.15.el5uek", rpm:"mlnx_en-2.6.32-400.37.15.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.37.15.el5uekdebug", rpm:"mlnx_en-2.6.32-400.37.15.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.37.15.el5uek", rpm:"ofa-2.6.32-400.37.15.el5uek~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.37.15.el5uekdebug", rpm:"ofa-2.6.32-400.37.15.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.37.15.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.37.15.el6uek", rpm:"mlnx_en-2.6.32-400.37.15.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.37.15.el6uekdebug", rpm:"mlnx_en-2.6.32-400.37.15.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.37.15.el6uek", rpm:"ofa-2.6.32-400.37.15.el6uek~1.5.1~4.0.58", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.37.15.el6uekdebug", rpm:"ofa-2.6.32-400.37.15.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6"))) {
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

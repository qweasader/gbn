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
  script_oid("1.3.6.1.4.1.25623.1.0.122801");
  script_cve_id("CVE-2015-5307", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2015-12-11 06:40:13 +0000 (Fri, 11 Dec 2015)");
  script_version("2022-04-05T09:12:43+0000");
  script_tag(name:"last_modification", value:"2022-04-05 09:12:43 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-3107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3107");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3107.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-118.2.2.el6uek, dtrace-modules-3.8.13-118.2.2.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-118.2.2]
- KVM: svm: unconditionally intercept #DB (Paolo Bonzini) [Orabug: 22333698] {CVE-2015-8104}
- KVM: x86: work around infinite loop in microcode when #AC is delivered (Eric Northup) [Orabug: 22333689] {CVE-2015-5307} {CVE-2015-5307}
- KVM: x86: Defining missing x86 vectors (Nadav Amit) [Orabug: 22333689]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-118.2.2.el6uek, dtrace-modules-3.8.13-118.2.2.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.2.2.el6uek", rpm:"dtrace-modules-3.8.13-118.2.2.el6uek~0.4.5~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.2.2.el6uek", rls:"OracleLinux6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.2.2.el7uek", rpm:"dtrace-modules-3.8.13-118.2.2.el7uek~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.2.2.el7uek", rls:"OracleLinux7"))) {
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

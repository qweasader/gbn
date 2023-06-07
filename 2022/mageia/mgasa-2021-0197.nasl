# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0197");
  script_cve_id("CVE-2021-2145", "CVE-2021-2250", "CVE-2021-2264", "CVE-2021-2266", "CVE-2021-2279", "CVE-2021-2280", "CVE-2021-2281", "CVE-2021-2282", "CVE-2021-2283", "CVE-2021-2284", "CVE-2021-2285", "CVE-2021-2286", "CVE-2021-2287", "CVE-2021-2291", "CVE-2021-2296", "CVE-2021-2297", "CVE-2021-2306", "CVE-2021-2309", "CVE-2021-2310");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-27 19:10:00 +0000 (Tue, 27 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0197");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0197.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28828");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27362");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27433");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27936");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28734");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixOVIR");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2021-0197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the upstream 6.1.20 maintenance release that fixes
at least the following security vulnerabilities:

A difficult to exploit vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows high privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of Oracle
VM VirtualBox (CVE-2021-2145, CVE-2021-2309, CVE-2021-2310).

An easily exploitable vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows high privileged attacker
with logon to the infrastructure where Oracle VM VirtualBox executes
to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle
VM VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of Oracle
VM VirtualBox (CVE-2021-2250).

An easily exploitable vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows low privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
creation, deletion or modification access to critical data or all Oracle
VM VirtualBox accessible data as well as unauthorized access to critical
data or complete access to all Oracle VM VirtualBox accessible data
(CVE-2021-2264).

An easily exploitable vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows high privileged attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized access
to critical data or complete access to all Oracle VM VirtualBox accessible
data (CVE-2021-2266, CVE-2021-2306).

A difficult to exploit vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows unauthenticated attacker with
network access via RDP to compromise Oracle VM VirtualBox. Successful
attacks of this vulnerability can result in takeover of Oracle VM
VirtualBox (CVE-2021-2279).

An easily exploitable vulnerability in the Oracle VM VirtualBox
(component: Core) prior to 6.1.20 allows unauthenticated attacker with
logon to the infrastructure where Oracle VM VirtualBox executes to
compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM
VirtualBox, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-virtualbox, virtualbox' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.30-desktop-1.mga7", rpm:"virtualbox-kernel-5.10.30-desktop-1.mga7~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.30-server-1.mga7", rpm:"virtualbox-kernel-5.10.30-server-1.mga7~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.30-desktop-1.mga8", rpm:"virtualbox-kernel-5.10.30-desktop-1.mga8~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.10.30-server-1.mga8", rpm:"virtualbox-kernel-5.10.30-server-1.mga8~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.20~1.1.mga8", rls:"MAGEIA8"))) {
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

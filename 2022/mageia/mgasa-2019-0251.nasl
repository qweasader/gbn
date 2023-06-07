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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0251");
  script_cve_id("CVE-2019-14809", "CVE-2019-9512", "CVE-2019-9514");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-05-12T12:25:31+0000");
  script_tag(name:"last_modification", value:"2022-05-12 12:25:31 +0000 (Thu, 12 May 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-09 00:15:00 +0000 (Wed, 09 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0251");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0251.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25372");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4503");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2019-0251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated golang packages fix security vulnerabilities:

Some HTTP/2 implementations are vulnerable to ping floods, potentially
leading to a denial of service. The attacker sends continual pings to an
HTTP/2 peer, causing the peer to build an internal queue of responses.
Depending on how efficiently this data is queued, this can consume excess
CPU, memory, or both (CVE-2019-9512)

Some HTTP/2 implementations are vulnerable to a reset flood, potentially
leading to a denial of service. The attacker opens a number of streams and
sends an invalid request over each stream that should solicit a stream of
RST_STREAM frames from the peer. Depending on how the peer queues the
RST_STREAM frames, this can consume excess memory, CPU, or both
(CVE-2019-9514).

net/url in Go before 1.11.13 and 1.12.x before 1.12.8 mishandles malformed
hosts in URLs, leading to an authorization bypass in some applications.
This is related to a Host field with a suffix appearing in neither
Hostname() nor Port(), and is related to a non-numeric port number.
(CVE-2019-14809)");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 6, Mageia 7.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.11.13~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.12.8~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.12.8~1.mga7", rls:"MAGEIA7"))) {
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

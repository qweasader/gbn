# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3264.1");
  script_cve_id("CVE-2020-15166");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 17:15:00 +0000 (Tue, 10 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3264-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203264-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zeromq' package(s) announced via the SUSE-SU-2020:3264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zeromq fixes the following issues:

CVE-2020-15166: Fixed the possibility of unauthenticated clients causing
 a denial-of-service (bsc#1176116).

Fixed a heap overflow when receiving malformed ZMTP v1 packets
 (bsc#1176256)

Fixed a memory leak in client induced by malicious server(s) without
 CURVE/ZAP (bsc#1176257)

Fixed memory leak when processing PUB messages with metadata
 (bsc#1176259)

Fixed a stack overflow in PUB/XPUB subscription store (bsc#1176258)");

  script_tag(name:"affected", value:"'zeromq' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libunwind", rpm:"libunwind~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-32bit", rpm:"libunwind-32bit~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-32bit-debuginfo", rpm:"libunwind-32bit-debuginfo~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debuginfo", rpm:"libunwind-debuginfo~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debugsource", rpm:"libunwind-debugsource~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-devel", rpm:"libunwind-devel~1.2.1~4.2.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-32bit", rpm:"libzmq5-32bit~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-32bit-debuginfo", rpm:"libzmq5-32bit-debuginfo~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-debuginfo", rpm:"libzmq5-debuginfo~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-debugsource", rpm:"zeromq-debugsource~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-devel", rpm:"zeromq-devel~4.2.3~3.15.4", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libunwind", rpm:"libunwind~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-32bit", rpm:"libunwind-32bit~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-32bit-debuginfo", rpm:"libunwind-32bit-debuginfo~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debuginfo", rpm:"libunwind-debuginfo~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debugsource", rpm:"libunwind-debugsource~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-devel", rpm:"libunwind-devel~1.2.1~4.2.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-32bit", rpm:"libzmq5-32bit~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-32bit-debuginfo", rpm:"libzmq5-32bit-debuginfo~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-debuginfo", rpm:"libzmq5-debuginfo~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-debugsource", rpm:"zeromq-debugsource~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-devel", rpm:"zeromq-devel~4.2.3~3.15.4", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libunwind", rpm:"libunwind~1.2.1~4.2.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debuginfo", rpm:"libunwind-debuginfo~1.2.1~4.2.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-debugsource", rpm:"libunwind-debugsource~1.2.1~4.2.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libunwind-devel", rpm:"libunwind-devel~1.2.1~4.2.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5", rpm:"libzmq5~4.2.3~3.15.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq5-debuginfo", rpm:"libzmq5-debuginfo~4.2.3~3.15.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-debugsource", rpm:"zeromq-debugsource~4.2.3~3.15.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zeromq-devel", rpm:"zeromq-devel~4.2.3~3.15.4", rls:"SLES15.0"))) {
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

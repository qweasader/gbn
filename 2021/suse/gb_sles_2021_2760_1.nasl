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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2760.1");
  script_cve_id("CVE-2021-3672");
  script_tag(name:"creation_date", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_version("2021-12-16T07:52:39+0000");
  script_tag(name:"last_modification", value:"2021-12-16 07:52:39 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 18:29:00 +0000 (Tue, 14 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2760-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212760-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c-ares' package(s) announced via the SUSE-SU-2021:2760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for c-ares fixes the following issues:

Version update to git snapshot 1.17.1+20200724:

CVE-2021-3672: fixed missing input validation on hostnames returned by
 DNS servers (bsc#1188881)

If ares_getaddrinfo() was terminated by an ares_destroy(), it would
 cause crash

Crash in sortaddrinfo() if the list size equals 0 due to an unexpected
 DNS response

Expand number of escaped characters in DNS replies as per RFC1035 5.1 to
 prevent spoofing

Use unbuffered /dev/urandom for random data to prevent early startup
 performance issues");

  script_tag(name:"affected", value:"'c-ares' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.17.1+20200724~3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.17.1+20200724~3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.17.1+20200724~3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.17.1+20200724~3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.17.1+20200724~3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.17.1+20200724~3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.17.1+20200724~3.14.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.17.1+20200724~3.14.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.17.1+20200724~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.17.1+20200724~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.17.1+20200724~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.17.1+20200724~3.14.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.17.1+20200724~3.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.17.1+20200724~3.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2", rpm:"libcares2~1.17.1+20200724~3.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcares2-debuginfo", rpm:"libcares2-debuginfo~1.17.1+20200724~3.14.1", rls:"SLES15.0SP1"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0456.1");
  script_cve_id("CVE-2017-16227", "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0456-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0456-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180456-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the SUSE-SU-2018:0456-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for quagga fixes the security following issues:
- The Quagga BGP daemon contained a bug in the AS_PATH size calculation
 that could have been exploited to facilitate a remote denial-of-service
 attack via specially crafted BGP UPDATE messages. [CVE-2017-16227,
 bsc#1065641]
- The Quagga BGP daemon did not check whether data sent to peers via
 NOTIFY had an invalid attribute length. It was possible to exploit this
 issue and cause the bgpd process to leak sensitive information over the
 network to a configured peer. [CVE-2018-5378, bsc#1079798]
- The Quagga BGP daemon used to double-free memory when processing certain
 forms of UPDATE messages. This issue could be exploited by sending an
 optional/transitive UPDATE attribute that all conforming eBGP speakers
 should pass along. Consequently, a single UPDATE message could have
 affected many bgpd processes across a wide area of a network. Through
 this vulnerability, attackers could potentially have taken over control
 of affected bgpd processes remotely. [CVE-2018-5379, bsc#1079799]
- It was possible to overrun internal BGP code-to-string conversion tables
 in the Quagga BGP daemon. Configured peers could have exploited this
 issue and cause bgpd to emit debug and warning messages into the logs
 that would contained arbitrary bytes. [CVE-2018-5380, bsc#1079800]
- The Quagga BGP daemon could have entered an infinite loop if sent an
 invalid OPEN message by a configured peer. If this issue was exploited,
 then bgpd would cease to respond to any other events. BGP sessions would
 have been dropped and not be reestablished. The CLI interface would have
 been unresponsive. The bgpd daemon would have stayed in this state until
 restarted. [CVE-2018-5381, bsc#1079801]");

  script_tag(name:"affected", value:"'quagga' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~17.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~17.7.1", rls:"SLES12.0SP3"))) {
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

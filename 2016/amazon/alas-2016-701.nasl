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
  script_oid("1.3.6.1.4.1.25623.1.0.120690");
  script_cve_id("CVE-2016-0639", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0705", "CVE-2016-2047");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:08 +0000 (Wed, 26 Oct 2016)");
  script_version("2021-12-20T13:08:45+0000");
  script_tag(name:"last_modification", value:"2021-12-20 13:08:45 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-19 19:33:00 +0000 (Tue, 19 Feb 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-701)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-701");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-701.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql56' package(s) announced via the ALAS-2016-701 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A double-free flaw was found in the way OpenSSL parsed certain malformed DSA (Digital Signature Algorithm) private keys. An attacker could create specially crafted DSA private keys that, when processed by an application compiled against OpenSSL, could cause the application to crash. (CVE-2016-0705)

The ssl_verify_server_cert function in sql-common/client.c in Oracle MySQL 5.6.29 and earlier does not properly verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via a '/CN=' string in a field in a certificate, as demonstrated by '/OU=/CN=bar.com/CN=foo.com'. (CVE-2016-2047)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Pluggable Authentication. (CVE-2016-0639)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect availability via vectors related to FTS. (CVE-2016-0647)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect integrity and availability via vectors related to Federated. (CVE-2016-0642)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect confidentiality via vectors related to DML. (CVE-2016-0643)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect availability via vectors related to Security: Privileges. (CVE-2016-0666)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect availability via vectors related to PS. (CVE-2016-0648)

Unspecified vulnerability in Oracle MySQL 5.6.29 and earlier allows local users to affect availability via vectors related to InnoDB. (CVE-2016-0655)");

  script_tag(name:"affected", value:"'mysql56' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mysql56", rpm:"mysql56~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-bench", rpm:"mysql56-bench~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-common", rpm:"mysql56-common~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-debuginfo", rpm:"mysql56-debuginfo~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-devel", rpm:"mysql56-devel~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-embedded", rpm:"mysql56-embedded~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-embedded-devel", rpm:"mysql56-embedded-devel~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-errmsg", rpm:"mysql56-errmsg~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-libs", rpm:"mysql56-libs~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-server", rpm:"mysql56-server~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-test", rpm:"mysql56-test~5.6.30~1.15.amzn1", rls:"AMAZON"))) {
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

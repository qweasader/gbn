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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0172.2");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0172-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0172-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150172-2/");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20150108.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2015:0172-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL has been updated to fix various security issues.

More information can be found in the OpenSSL advisory:
[link moved to references] .
The following issues have been fixed:
 *
 CVE-2014-3570: Bignum squaring (BN_sqr) may produce incorrect results
 on some platforms, including x86_64. (bsc#912296)
 *
 CVE-2014-3571: Fix crash in dtls1_get_record whilst in the listen state where you get two separate reads performed - one for the header and one for the body of the handshake record. (bsc#912294)
 *
 CVE-2014-3572: Don't accept a handshake using an ephemeral ECDH ciphersuites with the server key exchange message omitted. (bsc#912015)
 *
 CVE-2014-8275: Fix various certificate fingerprint issues.
(bsc#912018)
 *
 CVE-2015-0204: Only allow ephemeral RSA keys in export ciphersuites.
(bsc#912014)
 *
 CVE-2015-0205: OpenSSL 0.9.8j is NOT vulnerable to CVE-2015-0205 as it doesn't support DH certificates and this typo prohibits skipping
 of certificate verify message for sign only certificates anyway.
(bsc#912293)
Security Issues:
 * CVE-2014-8275
 * CVE-2014-3571
 * CVE-2015-0204
 * CVE-2014-3572
 * CVE-2014-3570
 * CVE-2015-0205");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac", rpm:"libopenssl0_9_8-hmac~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac-32bit", rpm:"libopenssl0_9_8-hmac-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8j~0.68.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac", rpm:"libopenssl0_9_8-hmac~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac-32bit", rpm:"libopenssl0_9_8-hmac-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8j~0.68.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac", rpm:"libopenssl0_9_8-hmac~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac-32bit", rpm:"libopenssl0_9_8-hmac-32bit~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-x86", rpm:"libopenssl0_9_8-x86~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8j~0.68.1", rls:"SLES11.0SP3"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.120744");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6306");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:28 +0000 (Wed, 26 Oct 2016)");
  script_version("2021-12-20T13:08:45+0000");
  script_tag(name:"last_modification", value:"2021-12-20 13:08:45 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-755)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-755");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-755.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2016-755 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL did not always use constant time operations when computing Digital Signature Algorithm (DSA) signatures. A local attacker could possibly use this flaw to obtain a private DSA key belonging to another user or service running on the same system. (CVE-2016-2178)

It was discovered that the Datagram TLS (DTLS) implementation could fail to release memory in certain cases. A malicious DTLS client could cause a DTLS server using OpenSSL to consume an excessive amount of memory and, possibly, exit unexpectedly after exhausting all available memory. (CVE-2016-2179)

A flaw was found in the Datagram TLS (DTLS) replay protection implementation in OpenSSL. A remote attacker could possibly use this flaw to make a DTLS server using OpenSSL to reject further packets sent from a DTLS client over an established DTLS connection. (CVE-2016-2181)

An out of bounds write flaw was discovered in the OpenSSL BN_bn2dec() function. An attacker able to make an application using OpenSSL to process a large BIGNUM could cause the application to crash or, possibly, execute arbitrary code. (CVE-2016-2182)

A flaw was found in the DES/3DES cipher was used as part of the TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to recover some plaintext data by capturing large amounts of encrypted traffic between TLS/SSL server and client if the communication used a DES/3DES based ciphersuite. (CVE-2016-2183)

An integer underflow flaw leading to a buffer over-read was found in the way OpenSSL parsed TLS session tickets. A remote attacker could use this flaw to crash a TLS server using OpenSSL if it used SHA-512 as HMAC for session tickets. (CVE-2016-6302)

Multiple integer overflow flaws were found in the way OpenSSL performed pointer arithmetic. A remote attacker could possibly use these flaws to cause a TLS/SSL server or client using OpenSSL to crash. (CVE-2016-2177)

An out of bounds read flaw was found in the way OpenSSL formatted Public Key Infrastructure Time-Stamp Protocol data for printing. An attacker could possibly cause an application using OpenSSL to crash if it printed time stamp data from the attacker. (CVE-2016-2180)

Multiple out of bounds read flaws were found in the way OpenSSL handled certain TLS/SSL protocol handshake messages. A remote attacker could possibly use these flaws to crash a TLS/SSL server or client using OpenSSL. (CVE-2016-6306)

This update mitigates the CVE-2016-2183 issue by lowering priority of DES cipher suites so they are not preferred over cipher suites using AES. For compatibility reasons, DES cipher suites remain enabled by default and included in the set of cipher suites identified by the HIGH cipher string. Future updates may move them to MEDIUM or not enable them by default.");

  script_tag(name:"affected", value:"'openssl' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~15.96.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~15.96.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~15.96.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~15.96.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~15.96.amzn1", rls:"AMAZON"))) {
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

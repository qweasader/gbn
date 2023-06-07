# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1040");
  script_cve_id("CVE-2015-3197", "CVE-2016-0800", "CVE-2016-2182", "CVE-2016-8610");
  script_tag(name:"creation_date", value:"2020-01-23 10:45:30 +0000 (Thu, 23 Jan 2020)");
  script_version("2021-07-22T02:24:02+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Huawei EulerOS: Security Advisory for openssl098e (EulerOS-SA-2017-1040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1040");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1040");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'openssl098e' package(s) announced via the EulerOS-SA-2017-1040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The BN_bn2dec function in crypto/bn/bn_print.c in OpenSSL before 1.1.0 does not properly validate division results, which allows remote attackers to cause a denial of service (out-of-bounds write and application crash) or possibly have unspecified other impact via unknown vectors.(CVE-2016-2182)

A denial of service flaw was found in the way the TLS/SSL protocol defined processing of ALERT packets during a connection handshake. A remote attacker could use this flaw to make a TLS/SSL server consume an excessive amount of CPU and fail to accept connections form other clients.(CVE-2016-8610)

A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2 ciphers that were disabled on the server. This could result in weak SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to man-in-the-middle attacks.(CVE-2015-3197)

A padding oracle flaw was found in the Secure Sockets Layer version 2.0 (SSLv2) protocol. An attacker could potentially use this flaw to decrypt RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol version, allowing them to decrypt such connections. This cross-protocol attack is publicly referred to as DROWN.(CVE-2016-0800)");

  script_tag(name:"affected", value:"'openssl098e' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.3.h2", rls:"EULEROS-2.0SP1"))) {
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

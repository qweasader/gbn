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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1254");
  script_cve_id("CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_tag(name:"creation_date", value:"2020-01-23 11:01:29 +0000 (Thu, 23 Jan 2020)");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-30 03:36:00 +0000 (Sat, 30 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for java-1.8.0-openjdk (EulerOS-SA-2017-1254)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1254");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1254");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'java-1.8.0-openjdk' package(s) announced via the EulerOS-SA-2017-1254 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were discovered in the RMI and Hotspot components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions. (CVE-2017-10285, CVE-2017-10346)

It was discovered that the Kerberos client implementation in the Libraries component of OpenJDK used the sname field from the plain text part rather than encrypted part of the KDC reply message. A man-in-the-middle attacker could possibly use this flaw to impersonate Kerberos services to Java applications acting as Kerberos clients. (CVE-2017-10388)

It was discovered that the Security component of OpenJDK generated weak password-based encryption keys used to protect private keys stored in key stores. This made it easier to perform password guessing attacks to decrypt stored keys if an attacker could gain access to a key store. (CVE-2017-10356)

A flaw was found in the Smart Card IO component in OpenJDK. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2017-10274)

It was found that the FtpClient implementation in the Networking component of OpenJDK did not set connect and read timeouts by default. A malicious FTP server or a man-in-the-middle attacker could use this flaw to block execution of a Java application connecting to an FTP server. (CVE-2017-10355)

It was found that the HttpURLConnection and HttpsURLConnection classes in the Networking component of OpenJDK failed to check for newline characters embedded in URLs. An attacker able to make a Java application perform an HTTP request using an attacker provided URL could possibly inject additional headers into the request. (CVE-2017-10295)

It was discovered that multiple classes in the JAXP, Serialization, Libraries, and JAX-WS components of OpenJDK did not limit the amount of memory allocated when creating object instances from the serialized form. A specially-crafted input could cause a Java application to use an excessive amount of memory when deserialized. (CVE-2017-10349, CVE-2017-10357, CVE-2017-10347, CVE-2017-10281, CVE-2017-10345, CVE-2017-10348, CVE-2017-10350)");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Huawei EulerOS V2.0SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.151~1.b12", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.151~1.b12", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.151~1.b12", rls:"EULEROS-2.0SP1"))) {
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

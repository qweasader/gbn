# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.120343");
  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_tag(name:"creation_date", value:"2015-09-08 11:24:08 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T03:03:10+0000");
  script_tag(name:"last_modification", value:"2022-01-07 03:03:10 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-430");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-430.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk' package(s) announced via the ALAS-2014-430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were discovered in the Libraries, 2D, and Hotspot components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2014-6506, CVE-2014-6531, CVE-2014-6502, CVE-2014-6511, CVE-2014-6504, CVE-2014-6519)

It was discovered that the StAX XML parser in the JAXP component in OpenJDK performed expansion of external parameter entities even when external entity substitution was disabled. A remote attacker could use this flaw to perform XML eXternal Entity (XXE) attack against applications using the StAX parser to parse untrusted XML documents. (CVE-2014-6517)

It was discovered that the DatagramSocket implementation in OpenJDK failed to perform source address checks for packets received on a connected socket. A remote attacker could use this flaw to have their packets processed as if they were received from the expected source. (CVE-2014-6512)

It was discovered that the TLS/SSL implementation in the JSSE component in OpenJDK failed to properly verify the server identity during the renegotiation following session resumption, making it possible for malicious TLS/SSL servers to perform a Triple Handshake attack against clients using JSSE and client certificate authentication. (CVE-2014-6457)

It was discovered that the CipherInputStream class implementation in OpenJDK did not properly handle certain exceptions. This could possibly allow an attacker to affect the integrity of an encrypted stream handled by this class. (CVE-2014-6558)");

  script_tag(name:"affected", value:"'java-1.6.0-openjdk' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.33~67.1.13.5.0.67.amzn1", rls:"AMAZON"))) {
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

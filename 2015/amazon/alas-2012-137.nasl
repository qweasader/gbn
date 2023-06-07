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
  script_oid("1.3.6.1.4.1.25623.1.0.120336");
  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5085", "CVE-2012-5086");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:51 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-06T14:03:07+0000");
  script_tag(name:"last_modification", value:"2022-01-06 14:03:07 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-137");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-137.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ALAS-2012-137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple improper permission check issues were discovered in the Beans, Swing, and JMX components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2012-5086, CVE-2012-5084, CVE-2012-5089)

Multiple improper permission check issues were discovered in the Scripting, JMX, Concurrency, Libraries, and Security components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2012-5068, CVE-2012-5071, CVE-2012-5069, CVE-2012-5073, CVE-2012-5072)

It was discovered that java.util.ServiceLoader could create an instance of an incompatible class while performing provider lookup. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions. (CVE-2012-5079)

It was discovered that the Java Secure Socket Extension (JSSE) SSL/TLS implementation did not properly handle handshake records containing an overly large data length value. An unauthenticated, remote attacker could possibly use this flaw to cause an SSL/TLS server to terminate with an exception. (CVE-2012-5081)

It was discovered that the JMX component in OpenJDK could perform certain actions in an insecure manner. An untrusted Java application or applet could possibly use this flaw to disclose sensitive information. (CVE-2012-5075)

A bug in the Java HotSpot Virtual Machine optimization code could cause it to not perform array initialization in certain cases. An untrusted Java application or applet could use this flaw to disclose portions of the virtual machine's memory. (CVE-2012-4416)

It was discovered that the SecureRandom class did not properly protect against the creation of multiple seeders. An untrusted Java application or applet could possibly use this flaw to disclose sensitive information. (CVE-2012-5077)

It was discovered that the java.io.FilePermission class exposed the hash code of the canonicalized path name. An untrusted Java application or applet could possibly use this flaw to determine certain system paths, such as the current working directory. (CVE-2012-3216)

This update disables Gopher protocol support in the java.net package by default. Gopher support can be enabled by setting the newly introduced property, 'jdk.net.registerGopherProtocol', to true. (CVE-2012-5085)");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.9~2.3.3.13.amzn1", rls:"AMAZON"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.120197");
  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");
  script_tag(name:"creation_date", value:"2015-09-08 11:19:47 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T03:03:10+0000");
  script_tag(name:"last_modification", value:"2022-01-07 03:03:10 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-235");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-235.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ALAS-2013-235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple input checking flaws were found in the 2D component native image parsing code. A specially crafted image file could trigger a Java Virtual Machine memory corruption and, possibly, lead to arbitrary code execution with the privileges of the user running the Java Virtual Machine. (CVE-2013-5782)

The class loader did not properly check the package access for non-public proxy classes. A remote attacker could possibly use this flaw to execute arbitrary code with the privileges of the user running the Java Virtual Machine. (CVE-2013-5830)

Multiple improper permission check issues were discovered in the 2D, CORBA, JNDI, and Libraries components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2013-5829, CVE-2013-5814, CVE-2013-5817, CVE-2013-5842, CVE-2013-5850, CVE-2013-5838)

Multiple input checking flaws were discovered in the JPEG image reading and writing code in the 2D component. An untrusted Java application or applet could use these flaws to corrupt the Java Virtual Machine memory and bypass Java sandbox restrictions. (CVE-2013-5809)

The FEATURE_SECURE_PROCESSING setting was not properly honored by the javax.xml.transform package transformers. A remote attacker could use this flaw to supply a crafted XML that would be processed without the intended security restrictions. (CVE-2013-5802)

Multiple errors were discovered in the way the JAXP and Security components processes XML inputs. A remote attacker could create a crafted XML that would cause a Java application to use an excessive amount of CPU and memory when processed. (CVE-2013-5825, CVE-2013-4002, CVE-2013-5823)

Multiple improper permission check issues were discovered in the Libraries, Swing, JAX-WS, JAXP, JGSS, AWT, Beans, and Scripting components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2013-3829, CVE-2013-5840, CVE-2013-5774, CVE-2013-5783, CVE-2013-5820, CVE-2013-5851, CVE-2013-5800, CVE-2013-5849, CVE-2013-5790, CVE-2013-5784)

It was discovered that the 2D component image library did not properly check bounds when performing image conversions. An untrusted Java application or applet could use this flaw to disclose portions of the Java Virtual Machine memory. (CVE-2013-5778)

Multiple input sanitization flaws were discovered in javadoc. When javadoc documentation was generated from an untrusted Java source code and hosted on a domain not controlled by the code author, these issues could make it easier to perform cross-site scripting attacks. (CVE-2013-5804, CVE-2013-5797)

Various OpenJDK classes that represent cryptographic keys could leak private key information by including sensitive data in strings returned by toString() methods. These flaws could possibly lead to an unexpected exposure of sensitive key data. (CVE-2013-5780)

The Java Heap ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-debuginfo", rpm:"java-1.7.0-openjdk-debuginfo~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.45~2.4.3.2.32.amzn1", rls:"AMAZON"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.120022");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2450", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2459", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:14 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-207)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-207");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-207.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk' package(s) announced via the ALAS-2013-207 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were discovered in the ImagingLib and the image attribute, channel, layout and raster processing in the 2D component. An untrusted Java application or applet could possibly use these flaws to trigger Java Virtual Machine memory corruption. (CVE-2013-2470, CVE-2013-2471, CVE-2013-2472, CVE-2013-2473, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469)

Integer overflow flaws were found in the way AWT processed certain input. An attacker could use these flaws to execute arbitrary code with the privileges of the user running an untrusted Java applet or application. (CVE-2013-2459)

Multiple improper permission check issues were discovered in the Sound and JMX components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass Java sandbox restrictions. (CVE-2013-2448, CVE-2013-2457, CVE-2013-2453)

Multiple flaws in the Serialization, Networking, Libraries and CORBA components can be exploited by an untrusted Java application or applet to gain access to potentially sensitive information. (CVE-2013-2456, CVE-2013-2447, CVE-2013-2455, CVE-2013-2452, CVE-2013-2443, CVE-2013-2446)

It was discovered that the Hotspot component did not properly handle out-of-memory errors. An untrusted Java application or applet could possibly use these flaws to terminate the Java Virtual Machine. (CVE-2013-2445)

It was discovered that the AWT component did not properly manage certain resources and that the ObjectStreamClass of the Serialization component did not properly handle circular references. An untrusted Java application or applet could possibly use these flaws to cause a denial of service. (CVE-2013-2444, CVE-2013-2450)

It was discovered that the Libraries component contained certain errors related to XML security and the class loader. A remote attacker could possibly exploit these flaws to bypass intended security mechanisms or disclose potentially sensitive information and cause a denial of service. (CVE-2013-2407, CVE-2013-2461)

It was discovered that JConsole did not properly inform the user when establishing an SSL connection failed. An attacker could exploit this flaw to gain access to potentially sensitive information. (CVE-2013-2412)

It was found that documentation generated by Javadoc was vulnerable to a frame injection attack. If such documentation was accessible over a network, and a remote attacker could trick a user into visiting a specially-crafted URL, it would lead to arbitrary web content being displayed next to the documentation. This could be used to perform a phishing attack by providing frame content that spoofed a login form on the site hosting the vulnerable documentation. (CVE-2013-1571)

It was discovered that the 2D component created shared memory segments with insecure permissions. A local attacker could use this flaw to read or write to the shared memory segment. (CVE-2013-1500)");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~62.1.11.11.90.55.amzn1", rls:"AMAZON"))) {
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

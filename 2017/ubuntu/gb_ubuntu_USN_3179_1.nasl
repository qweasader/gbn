# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.843026");
  script_cve_id("CVE-2016-2183", "CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5549", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");
  script_tag(name:"creation_date", value:"2017-01-26 04:43:44 +0000 (Thu, 26 Jan 2017)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3179-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3179-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8' package(s) announced via the USN-3179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karthik Bhargavan and Gaetan Leurent discovered that the DES and
Triple DES ciphers were vulnerable to birthday attacks. A remote
attacker could possibly use this flaw to obtain clear text data from
long encrypted sessions. This update moves those algorithms to the
legacy algorithm set and causes them to be used only if no non-legacy
algorithms can be negotiated. (CVE-2016-2183)

It was discovered that OpenJDK accepted ECSDA signatures using
non-canonical DER encoding. An attacker could use this to modify or
expose sensitive data. (CVE-2016-5546)

It was discovered that OpenJDK did not properly verify object
identifier (OID) length when reading Distinguished Encoding Rules
(DER) records, as used in x.509 certificates and elsewhere. An
attacker could use this to cause a denial of service (memory
consumption). (CVE-2016-5547)

It was discovered that covert timing channel vulnerabilities existed
in the DSA and ECDSA implementations in OpenJDK. A remote attacker
could use this to expose sensitive information. (CVE-2016-5548,
CVE-2016-5549)

It was discovered that the URLStreamHandler class in OpenJDK did not
properly parse user information from a URL. A remote attacker could
use this to expose sensitive information. (CVE-2016-5552)

It was discovered that the URLClassLoader class in OpenJDK did not
properly check access control context when downloading class files. A
remote attacker could use this to expose sensitive information.
(CVE-2017-3231)

It was discovered that the Remote Method Invocation (RMI)
implementation in OpenJDK performed deserialization of untrusted
inputs. A remote attacker could use this to execute arbitrary
code. (CVE-2017-3241)

It was discovered that the Java Authentication and Authorization
Service (JAAS) component of OpenJDK did not properly perform user
search LDAP queries. An attacker could use a specially constructed
LDAP entry to expose or modify sensitive information. (CVE-2017-3252)

It was discovered that the PNGImageReader class in OpenJDK did not
properly handle iTXt and zTXt chunks. An attacker could use this to
cause a denial of service (memory consumption). (CVE-2017-3253)

It was discovered that integer overflows existed in the
SocketInputStream and SocketOutputStream classes of OpenJDK. An
attacker could use this to expose sensitive information.
(CVE-2017-3261)

It was discovered that the atomic field updaters in the
java.util.concurrent.atomic package in OpenJDK did not properly
restrict access to protected field members. An attacker could use
this to specially craft a Java application or applet that could bypass
Java sandbox restrictions. (CVE-2017-3272)

It was discovered that a vulnerability existed in the class
construction implementation in OpenJDK. An attacker could use this
to specially craft a Java application or applet that could bypass
Java sandbox restrictions. (CVE-2017-3289)");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk-headless", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u121-b13-0ubuntu1.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk-headless", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u121-b13-0ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
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

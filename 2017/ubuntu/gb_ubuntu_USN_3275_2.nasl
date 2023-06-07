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
  script_oid("1.3.6.1.4.1.25623.1.0.843173");
  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_tag(name:"creation_date", value:"2017-05-17 04:54:55 +0000 (Wed, 17 May 2017)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3275-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3275-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3275-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-3275-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3275-1 fixed vulnerabilities in OpenJDK 8. This update provides
the corresponding updates for OpenJDK 7.

Original advisory details:

It was discovered that OpenJDK improperly re-used cached NTLM
connections in some situations. A remote attacker could possibly
use this to cause a Java application to perform actions with the
credentials of a different user. (CVE-2017-3509)

It was discovered that an untrusted library search path flaw existed
in the Java Cryptography Extension (JCE) component of OpenJDK. A
local attacker could possibly use this to gain the privileges of a
Java application. (CVE-2017-3511)

It was discovered that the Java API for XML Processing (JAXP) component
in OpenJDK did not properly enforce size limits when parsing XML
documents. An attacker could use this to cause a denial of service
(processor and memory consumption). (CVE-2017-3526)

It was discovered that the FTP client implementation in OpenJDK did
not properly sanitize user inputs. If a user was tricked into opening
a specially crafted FTP URL, a remote attacker could use this to
manipulate the FTP connection. (CVE-2017-3533)

It was discovered that OpenJDK allowed MD5 to be used as an algorithm
for JAR integrity verification. An attacker could possibly use this
to modify the contents of a JAR file without detection. (CVE-2017-3539)

It was discovered that the SMTP client implementation in OpenJDK
did not properly sanitize sender and recipient addresses. A remote
attacker could use this to specially craft email addresses and gain
control of a Java application's SMTP connections. (CVE-2017-3544)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u131-2.6.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u131-2.6.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u131-2.6.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u131-2.6.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u131-2.6.9-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
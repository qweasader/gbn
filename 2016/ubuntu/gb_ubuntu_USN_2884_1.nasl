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
  script_oid("1.3.6.1.4.1.25623.1.0.842630");
  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2016-02-05 07:44:38 +0000 (Fri, 05 Feb 2016)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-2884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2884-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2884-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the OpenJDK JRE related
to information disclosure, data integrity, and availability. An
attacker could exploit these to cause a denial of service, expose
sensitive data over the network, or possibly execute arbitrary code.
(CVE-2016-0483, CVE-2016-0494)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this to expose sensitive data
over the network or possibly execute arbitrary code. (CVE-2016-0402)

It was discovered that OpenJDK 7 incorrectly allowed MD5 to be used
for TLS connections. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could be exploited to expose
sensitive information. (CVE-2015-7575)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit this to expose
sensitive data over the network. (CVE-2016-0448)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit this to cause a denial of
service. (CVE-2016-0466)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u95-2.6.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u95-2.6.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u95-2.6.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u95-2.6.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u95-2.6.4-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u95-2.6.4-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u95-2.6.4-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u95-2.6.4-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u95-2.6.4-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u95-2.6.4-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u95-2.6.4-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u95-2.6.4-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u95-2.6.4-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u95-2.6.4-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u95-2.6.4-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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

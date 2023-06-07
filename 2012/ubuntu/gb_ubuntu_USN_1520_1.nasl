# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.841097");
  script_cve_id("CVE-2012-1012", "CVE-2012-1013", "CVE-2012-1014", "CVE-2012-1015");
  script_tag(name:"creation_date", value:"2012-08-03 05:47:37 +0000 (Fri, 03 Aug 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1520-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1520-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1520-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-1520-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
(KDC) daemon could free an uninitialized pointer when handling a
malformed AS-REQ message. A remote unauthenticated attacker could
use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2012-1015)

Emmanuel Bouillon discovered that the MIT krb5 Key Distribution Center
(KDC) daemon could dereference an uninitialized pointer while handling
a malformed AS-REQ message. A remote unauthenticated attacker could
use this to cause a denial of service or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS. (CVE-2012-1014)

Simo Source discovered that the MIT krb5 Key Distribution Center (KDC)
daemon could dereference a NULL pointer when handling a malformed
TGS-REQ message. A remote authenticated attacker could use this to
cause a denial of service. (CVE-2012-1013)

It was discovered that the kadmin protocol implementation in MIT krb5
did not properly restrict access to the SET_STRING and GET_STRINGS
operations. A remote authenticated attacker could use this to expose
or modify sensitive information. This issue only affected Ubuntu
12.04 LTS. (CVE-2012-1012)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.1+dfsg-2ubuntu0.11", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.1+dfsg-2ubuntu0.11", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.1+dfsg-2ubuntu0.11", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.3+dfsg-5ubuntu2.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.3+dfsg-5ubuntu2.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.3+dfsg-5ubuntu2.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.9.1+dfsg-1ubuntu2.3", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.9.1+dfsg-1ubuntu2.3", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.9.1+dfsg-1ubuntu2.3", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10+dfsg~beta1-2ubuntu0.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10+dfsg~beta1-2ubuntu0.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10+dfsg~beta1-2ubuntu0.3", rls:"UBUNTU12.04 LTS"))) {
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
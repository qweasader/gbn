# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.64782");
  script_cve_id("CVE-2008-3422", "CVE-2008-3906", "CVE-2009-0217");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-826-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-826-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-826-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mono' package(s) announced via the USN-826-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the XML HMAC signature system did not correctly
check certain lengths. If an attacker sent a truncated HMAC, it could
bypass authentication, leading to potential privilege escalation.
(CVE-2009-0217)

It was discovered that Mono did not properly escape certain attributes in
the ASP.net class libraries which could result in browsers becoming
vulnerable to cross-site scripting attacks when processing the output. With
cross-site scripting vulnerabilities, if a user were tricked into viewing
server output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain. This issue only affected Ubuntu 8.04
LTS. (CVE-2008-3422)

It was discovered that Mono did not properly filter CRLF injections in the
query string. If a user were tricked into viewing server output during a
crafted server request, a remote attacker could exploit this to modify the
contents, steal confidential data (such as passwords), or perform
cross-site request forgeries. This issue only affected Ubuntu 8.04 LTS.
(CVE-2008-3906)");

  script_tag(name:"affected", value:"'mono' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"1.2.6+dfsg-6ubuntu3.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"1.9.1+dfsg-4ubuntu2.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.0.1-4ubuntu0.1", rls:"UBUNTU9.04"))) {
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
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
  script_oid("1.3.6.1.4.1.25623.1.0.841219");
  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
  script_tag(name:"creation_date", value:"2012-11-23 06:20:54 +0000 (Fri, 23 Nov 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:31:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1636-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1636-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1636-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1080212");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1636-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gary Kwong, Jesse Ruderman, Christian Holler, Bob Clary, Kyle Huey, Ed
Morley, Chris Lord, Boris Zbarsky, Julian Seward, Bill McCloskey, and
Andrew McCreight discovered several memory corruption flaws in Thunderbird.
If a user were tricked into opening a malicious website and had JavaScript
enabled, an attacker could exploit these to execute arbitrary JavaScript
code within the context of another website or arbitrary code as the user
invoking the program. (CVE-2012-5842, CVE-2012-5843)

Atte Kettunen discovered a buffer overflow while rendering GIF format
images. An attacker could exploit this to possibly execute arbitrary code
as the user invoking Thunderbird. (CVE-2012-4202)

It was discovered that the evalInSandbox function's JavaScript sandbox
context could be circumvented. An attacker could exploit this to perform a
cross-site scripting (XSS) attack or steal a copy of a local file if the
user has installed an add-on vulnerable to this attack. With cross-site
scripting vulnerabilities, if a user were tricked into viewing a specially
crafted page and had JavaScript enabled, a remote attacker could exploit
this to modify the contents, or steal confidential data, within the same
domain. (CVE-2012-4201)

Jonathan Stephens discovered that combining vectors involving the setting
of Cascading Style Sheets (CSS) properties in conjunction with SVG text
could cause Thunderbird to crash. If a user were tricked into opening a
malicious E-Mail, an attacker could cause a denial of service via
application crash or execute arbitrary code with the privliges of the user
invoking the program. (CVE-2012-5836)

Scott Bell discovered a memory corruption issue in the JavaScript engine.
If a user were tricked into opening a malicious website and had JavaScript
enabled, an attacker could exploit this to execute arbitrary JavaScript
code within the context of another website or arbitrary code as the user
invoking the program. (CVE-2012-4204)

Gabor Krizsanits discovered that XMLHttpRequest objects created within
sandboxes have the system principal instead of the sandbox principal. This
can lead to cross-site request forgery (CSRF) or information theft via an
add-on running untrusted code in a sandbox. (CVE-2012-4205)

Peter Van der Beken discovered XrayWrapper implementation in Firefox does
not consider the compartment during property filtering. If JavaScript were
enabled, an attacker could use this to bypass intended chrome-only
restrictions on reading DOM object properties via a crafted web site.
(CVE-2012-4208)

Bobby Holley discovered that cross-origin wrappers were allowing write
actions on objects when only read actions should have been properly
allowed. This can lead to cross-site scripting (XSS) attacks. With
cross-site scripting vulnerabilities, if a user were tricked into viewing a
specially crafted page and had JavaScript enabled, a remote attacker could
exploit this to modify the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"17.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
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

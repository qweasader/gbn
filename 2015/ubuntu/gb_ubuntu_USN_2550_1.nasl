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
  script_oid("1.3.6.1.4.1.25623.1.0.842152");
  script_cve_id("CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816");
  script_tag(name:"creation_date", value:"2015-04-02 05:13:05 +0000 (Thu, 02 Apr 2015)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2550-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2550-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2550-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2550-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Olli Pettay and Boris Zbarsky discovered an issue during anchor
navigations in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit this
to bypass same-origin policy restrictions. (CVE-2015-0801)

Bobby Holley discovered that windows created to hold privileged UI content
retained access to privileged internal methods if navigated to
unprivileged content. An attacker could potentially exploit this in
combination with another flaw, in order to execute arbitrary script in a
privileged context. (CVE-2015-0802)

Several type confusion issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-0803, CVE-2015-0804)

Abhishek Arya discovered memory corruption issues during 2D graphics
rendering. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-0805, CVE-2015-0806)

Christoph Kerschbaumer discovered that CORS requests from
navigator.sendBeacon() followed 30x redirections after preflight. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to conduct cross-site request forgery
(XSRF) attacks. (CVE-2015-0807)

Mitchell Harper discovered an issue with memory management of simple-type
arrays in WebRTC. An attacker could potentially exploit this to cause
undefined behaviour. (CVE-2015-0808)

Felix Grobert discovered an out-of-bounds read in the QCMS colour
management library. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2015-0811)

Armin Razmdjou discovered that lightweight themes could be installed
in Firefox without a user approval message, from Mozilla subdomains
over HTTP without SSL. A remote attacker could potentially exploit this by
conducting a Machine-In-The-Middle (MITM) attack to install themes without
user approval. (CVE-2015-0812)

Aki Helin discovered a use-after-free when playing MP3 audio files using
the Fluendo MP3 GStreamer plugin in certain circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-0813)

Christian Holler, Andrew McCreight, Gary Kwong, Karl Tomlinson, Randell
Jesup, Shu-yu Guo, Steve Fink, Tooru Fujisawa, and Byron Campen discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.14.10.1", rls:"UBUNTU14.10"))) {
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

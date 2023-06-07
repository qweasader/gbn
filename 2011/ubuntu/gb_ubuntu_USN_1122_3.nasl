# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840675");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_tag(name:"creation_date", value:"2011-06-10 14:29:51 +0000 (Fri, 10 Jun 2011)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1122-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1122-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1122-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/777619");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1122-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1122-2 fixed vulnerabilities in Thunderbird on Ubuntu 11.04. A
regression was introduced which caused Thunderbird to display an empty menu
bar. This update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 It was discovered that there was a vulnerability in the memory handling of
 certain types of content. An attacker could exploit this to possibly run
 arbitrary code as the user running Thunderbird. (CVE-2011-0081)

 It was discovered that Thunderbird incorrectly handled certain JavaScript
 requests. If JavaScript were enabled, an attacker could exploit this to
 possibly run arbitrary code as the user running Thunderbird.
 (CVE-2011-0069)

 Ian Beer discovered a vulnerability in the memory handling of a certain
 types of documents. An attacker could exploit this to possibly run
 arbitrary code as the user running Thunderbird. (CVE-2011-0070)

 Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and Jesse Ruderman
 discovered several memory vulnerabilities. An attacker could exploit these
 to possibly run arbitrary code as the user running Thunderbird.
 (CVE-2011-0080)

 Aki Helin discovered multiple vulnerabilities in the HTML rendering code.
 An attacker could exploit these to possibly run arbitrary code as the user
 running Thunderbird. (CVE-2011-0074, CVE-2011-0075)

 Ian Beer discovered multiple overflow vulnerabilities. An attacker could
 exploit these to possibly run arbitrary code as the user running
 Thunderbird. (CVE-2011-0077, CVE-2011-0078)

 Martin Barbella discovered a memory vulnerability in the handling of
 certain DOM elements. An attacker could exploit this to possibly run
 arbitrary code as the user running Thunderbird. (CVE-2011-0072)

 It was discovered that there were use-after-free vulnerabilities in
 Thunderbird's mChannel and mObserverList objects. An attacker could exploit
 these to possibly run arbitrary code as the user running Thunderbird.
 (CVE-2011-0065, CVE-2011-0066)

 It was discovered that there was a vulnerability in the handling of the
 nsTreeSelection element. An attacker sending a specially crafted E-Mail
 could exploit this to possibly run arbitrary code as the user running
 Thunderbird. (CVE-2011-0073)

 Paul Stone discovered a vulnerability in the handling of Java applets. If
 plugins were enabled, an attacker could use this to mimic interaction with
 form autocomplete controls and steal entries from the form history.
 (CVE-2011-0067)

 Soroush Dalili discovered a vulnerability in the resource: protocol. This
 could potentially allow an attacker to load arbitrary files that were
 accessible to the user running Thunderbird. (CVE-2011-0071)

 Chris Evans discovered a vulnerability in Thunderbird's XSLT generate-id()
 function. An attacker could possibly use this vulnerability to make other
 attacks more reliable. (CVE-2011-1202)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-globalmenu", ver:"3.1.10+build1+nobinonly-0ubuntu0.11.04.2", rls:"UBUNTU11.04"))) {
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

# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5782.1");
  script_cve_id("CVE-2022-46871", "CVE-2022-46872", "CVE-2022-46873", "CVE-2022-46874", "CVE-2022-46877", "CVE-2022-46878", "CVE-2022-46879");
  script_tag(name:"creation_date", value:"2022-12-16 04:10:24 +0000 (Fri, 16 Dec 2022)");
  script_version("2023-01-06T10:11:13+0000");
  script_tag(name:"last_modification", value:"2023-01-06 10:11:13 +0000 (Fri, 06 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 15:57:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5782-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5782-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Firefox was using an out-of-date libusrsctp library.
An attacker could possibly use this library to perform a reentrancy issue
on Firefox. (CVE-2022-46871)

Nika Layzell discovered that Firefox was not performing a check on paste
received from cross-processes. An attacker could potentially exploit this
to obtain sensitive information. (CVE-2022-46872)

Pete Freitag discovered that Firefox did not implement the unsafe-hashes
CSP directive. An attacker who was able to inject markup into a page
otherwise protected by a Content Security Policy may have been able to
inject an executable script. (CVE-2022-46873)

Matthias Zoellner discovered that Firefox was not keeping the filename
ending intact when using the drag-and-drop event. An attacker could
possibly use this issue to add a file with a malicious extension, leading
to execute arbitrary code. (CVE-2022-46874)

Hafiizh discovered that Firefox was not handling fullscreen notifications
when the browser window goes into fullscreen mode. An attacker could
possibly use this issue to spoof the user and obtain sensitive information.
(CVE-2022-46877)

Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information across domains, or execute arbitrary code. (CVE-2022-46878,
CVE-2022-46879)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"108.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"108.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704521");
  script_cve_id("CVE-2019-13139", "CVE-2019-13509", "CVE-2019-14271");
  script_tag(name:"creation_date", value:"2019-09-11 02:00:11 +0000 (Wed, 11 Sep 2019)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:03:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-4521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4521");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4521");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4521");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/docker.io");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'docker.io' package(s) announced via the DSA-4521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three security vulnerabilities have been discovered in the Docker container runtime: Insecure loading of NSS libraries in docker cp could result in execution of code with root privileges, sensitive data could be logged in debug mode and there was a command injection vulnerability in the docker build command.

For the stable distribution (buster), these problems have been fixed in version 18.09.1+dfsg1-7.1+deb10u1.

We recommend that you upgrade your docker.io packages.

For the detailed security status of docker.io please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'docker.io' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"docker-doc", ver:"18.09.1+dfsg1-7.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"docker.io", ver:"18.09.1+dfsg1-7.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-docker-dev", ver:"18.09.1+dfsg1-7.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-docker-docker-dev", ver:"18.09.1+dfsg1-7.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-syntax-docker", ver:"18.09.1+dfsg1-7.1+deb10u1", rls:"DEB10"))) {
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
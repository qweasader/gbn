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
  script_oid("1.3.6.1.4.1.25623.1.0.703473");
  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");
  script_tag(name:"creation_date", value:"2016-02-10 23:00:00 +0000 (Wed, 10 Feb 2016)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:13:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-3473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3473");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3473");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nginx' package(s) announced via the DSA-3473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the resolver in nginx, a small, powerful, scalable web/proxy server, leading to denial of service or, potentially, to arbitrary code execution. These only affect nginx if the resolver directive is used in a configuration file.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.2.1-2.2+wheezy4.

For the stable distribution (jessie), these problems have been fixed in version 1.6.2-5+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1.9.10-1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.10-1.

We recommend that you upgrade your nginx packages.");

  script_tag(name:"affected", value:"'nginx' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-doc", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras-dbg", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full-dbg", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light-dbg", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-naxsi-dbg", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-naxsi-ui", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-naxsi", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx", ver:"1.2.1-2.2+wheezy4", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"nginx-common", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-doc", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras-dbg", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-extras", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full-dbg", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-full", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light-dbg", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx-light", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nginx", ver:"1.6.2-5+deb8u1", rls:"DEB8"))) {
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

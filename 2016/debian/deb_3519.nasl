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
  script_oid("1.3.6.1.4.1.25623.1.0.703519");
  script_cve_id("CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8550", "CVE-2015-8555", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-2270", "CVE-2016-2271");
  script_tag(name:"creation_date", value:"2016-03-16 23:00:00 +0000 (Wed, 16 Mar 2016)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3519)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3519");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3519");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3519");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3519 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Xen virtualisation solution, which may result in denial of service or information disclosure.

The oldstable distribution (wheezy) will be updated in a separate DSA.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.4", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-amd64", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-arm64", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.4-armhf", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.4", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.4.1-9+deb8u4", rls:"DEB8"))) {
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

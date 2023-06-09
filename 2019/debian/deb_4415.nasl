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
  script_oid("1.3.6.1.4.1.25623.1.0.704415");
  script_cve_id("CVE-2017-16355");
  script_tag(name:"creation_date", value:"2019-03-23 22:00:00 +0000 (Sat, 23 Mar 2019)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-28 15:31:00 +0000 (Mon, 28 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4415)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4415");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4415");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4415");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/passenger");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'passenger' package(s) announced via the DSA-4415 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An arbitrary file read vulnerability was discovered in passenger, a web application server. A local user allowed to deploy an application to passenger, can take advantage of this flaw by creating a symlink from the REVISION file to an arbitrary file on the system and have its content displayed through passenger-status.

For the stable distribution (stretch), this problem has been fixed in version 5.0.30-1+deb9u1.

We recommend that you upgrade your passenger packages.

For the detailed security status of passenger please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'passenger' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-passenger", ver:"5.0.30-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passenger-doc", ver:"5.0.30-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passenger", ver:"5.0.30-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-passenger-doc", ver:"5.0.30-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-passenger", ver:"5.0.30-1+deb9u1", rls:"DEB9"))) {
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

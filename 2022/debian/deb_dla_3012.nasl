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
  script_oid("1.3.6.1.4.1.25623.1.0.893012");
  script_cve_id("CVE-2022-29824");
  script_tag(name:"creation_date", value:"2022-05-18 05:50:21 +0000 (Wed, 18 May 2022)");
  script_version("2023-03-09T10:20:44+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:44 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 14:53:00 +0000 (Tue, 10 May 2022)");

  script_name("Debian: Security Advisory (DLA-3012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3012");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3012");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxml2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DLA-3012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm discovered that libxml2, the GNOME XML library, did not correctly check for integer overflows or used wrong types for buffer sizes. This could result in out-of-bounds writes or other memory errors when working on large, multi-gigabyte buffers.

For Debian 9 stretch, this problem has been fixed in version 2.9.4+dfsg1-2.2+deb9u7.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils-dbg", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libxml2", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2-dbg", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.9.4+dfsg1-2.2+deb9u7", rls:"DEB9"))) {
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

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
  script_oid("1.3.6.1.4.1.25623.1.0.892883");
  script_cve_id("CVE-2021-46141", "CVE-2021-46142");
  script_tag(name:"creation_date", value:"2022-01-18 02:00:05 +0000 (Tue, 18 Jan 2022)");
  script_version("2023-03-30T10:19:37+0000");
  script_tag(name:"last_modification", value:"2023-03-30 10:19:37 +0000 (Thu, 30 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-12 18:30:00 +0000 (Wed, 12 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2883)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2883");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2883-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uriparser' package(s) announced via the DLA-2883 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the fix for CVE-2021-46141 released in uriparser version 0.8.4-1+deb9u3 was incomplete.

CVE-2021-46141

An issue was discovered in uriparser before 0.9.6. It performs invalid free operations in uriFreeUriMembers and uriMakeOwner.

For Debian 9 Stretch, these problems have been fixed in version 0.8.4-1+deb9u4.

We recommend that you upgrade your packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'uriparser' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liburiparser-dev", ver:"0.8.4-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liburiparser-doc", ver:"0.8.4-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liburiparser1", ver:"0.8.4-1+deb9u3", rls:"DEB9"))) {
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

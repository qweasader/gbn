# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704954");
  script_cve_id("CVE-2021-3672");
  script_tag(name:"creation_date", value:"2021-08-12 03:00:06 +0000 (Thu, 12 Aug 2021)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 18:29:00 +0000 (Tue, 14 Dec 2021)");

  script_name("Debian: Security Advisory (DSA-4954)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4954");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4954");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4954");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/c-ares");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'c-ares' package(s) announced via the DSA-4954 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Philipp Jeitner and Haya Shulman discovered a flaw in c-ares, a library that performs DNS requests and name resolution asynchronously. Missing input validation of hostnames returned by DNS servers can lead to output of wrong hostnames (leading to Domain Hijacking).

For the stable distribution (buster), this problem has been fixed in version 1.14.0-1+deb10u1.

We recommend that you upgrade your c-ares packages.

For the detailed security status of c-ares please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'c-ares' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libc-ares-dev", ver:"1.14.0-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-ares2", ver:"1.14.0-1+deb10u1", rls:"DEB10"))) {
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

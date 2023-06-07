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
  script_oid("1.3.6.1.4.1.25623.1.0.820158");
  script_version("2022-03-31T07:10:52+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-31 07:10:52 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-27 01:06:38 +0000 (Sun, 27 Mar 2022)");
  script_name("Fedora: Security Advisory for GeographicLib (FEDORA-2022-6746739d52)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-6746739d52");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DH3AT2K3NMW2YMYUWD26JRLYFVKKIIWO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GeographicLib'
  package(s) announced via the FEDORA-2022-6746739d52 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GeographicLib is a small set of C++ classes for performing conversions
between geographic, UTM, UPS, MGRS, geocentric, and local Cartesian
coordinates, for gravity (e.g., EGM2008), geoid height and geomagnetic
field (e.g., WMM2010) calculations, and for solving geodesic problems.
The emphasis is on returning accurate results with errors close to round-off
(about 515 nanometers). New accurate algorithms for Geodesics on an
ellipsoid of revolution and Transverse Mercator projection have been
developed for this library. The functionality of the library can be accessed
from user code, from the Utility programs provided, or via the
Implementations in other languages.");

  script_tag(name:"affected", value:"'GeographicLib' package(s) on Fedora 36.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"GeographicLib", rpm:"GeographicLib~1.52~7.fc36", rls:"FC36"))) {
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
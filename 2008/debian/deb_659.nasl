# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.53492");
  script_cve_id("CVE-2004-1340", "CVE-2005-0108");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-659");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-659");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-659");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-radius-auth' package(s) announced via the DSA-659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two problems have been discovered in the libpam-radius-auth package, the PAM RADIUS authentication module. The Common Vulnerabilities and Exposures Project identifies the following problems:

CAN-2004-1340

The Debian package accidentally installed its configuration file /etc/pam_radius_auth.conf world-readable. Since it may possibly contain secrets all local users are able to read them if the administrator hasn't adjusted file permissions. This problem is Debian specific.

CAN-2005-0108

Leon Juranic discovered an integer underflow in the mod_auth_radius module for Apache which is also present in libpam-radius-auth.

For the stable distribution (woody) these problems have been fixed in version 1.3.14-1.3.

For the unstable distribution (sid) these problems have been fixed in version 1.3.16-3.

We recommend that you upgrade your libpam-radius-auth package.");

  script_tag(name:"affected", value:"'libpam-radius-auth' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-radius-auth", ver:"1.3.14-1.3", rls:"DEB3.0"))) {
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

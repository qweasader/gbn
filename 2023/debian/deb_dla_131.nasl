# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.131");
  script_cve_id("CVE-2014-8116", "CVE-2014-8117");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:20:44+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:20:44 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DLA-131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-131");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-131");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'file' package(s) announced via the DLA-131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in file, a tool/library to determine a file type. Processing a malformed file could result in denial of service. Most of the changes are related to parsing ELF files.

As part of the fixes, several limits on aspects of the detection were added or tightened, sometimes resulting in messages like recursion limit exceeded or too many program header sections.

To mitigate such shortcomings, these limits are controllable by a new '-R'/'--recursion' parameter in the file program. Note: A future upgrade for file in squeeze-lts might replace this with the '-P' parameter to keep usage consistent across all distributions.

CVE-2014-8116

The ELF parser (readelf.c) allows remote attackers to cause a denial of service (CPU consumption or crash).

CVE-2014-8117

softmagic.c does not properly limit recursion, which allows remote attackers to cause a denial of service (CPU consumption or crash).

(no identifier has been assigned so far)

out-of-bounds memory access

For Debian 6 Squeeze, these issues have been fixed in file version 5.04-5+squeeze9");

  script_tag(name:"affected", value:"'file' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"file", ver:"5.04-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic-dev", ver:"5.04-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagic1", ver:"5.04-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic-dbg", ver:"5.04-5+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-magic", ver:"5.04-5+squeeze9", rls:"DEB6"))) {
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

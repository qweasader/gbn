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
  script_oid("1.3.6.1.4.1.25623.1.0.61933");
  script_cve_id("CVE-2008-3863", "CVE-2008-4306", "CVE-2008-5078");
  script_tag(name:"creation_date", value:"2008-12-03 17:25:22 +0000 (Wed, 03 Dec 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1670)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1670");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1670");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1670");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'enscript' package(s) announced via the DSA-1670 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Enscript, a converter from ASCII text to Postscript, HTML or RTF. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3863

Ulf Harnhammer discovered that a buffer overflow may lead to the execution of arbitrary code.

CVE-2008-4306

Kees Cook and Tomas Hoger discovered that several buffer overflows may lead to the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 1.6.4-11.1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 1.6.4-13.

We recommend that you upgrade your enscript package.");

  script_tag(name:"affected", value:"'enscript' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"enscript", ver:"1.6.4-11.1", rls:"DEB4"))) {
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

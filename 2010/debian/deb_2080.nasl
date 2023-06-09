# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.67835");
  script_cve_id("CVE-2007-6725", "CVE-2008-3522", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0792", "CVE-2009-4270", "CVE-2010-1869");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2080");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2080");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2080");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ghostscript' package(s) announced via the DSA-2080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in Ghostscript, a GPL PostScript/PDF interpreter, which might lead to the execution of arbitrary code if a user processes a malformed PDF or Postscript file.

For the stable distribution (lenny), these problems have been fixed in version 8.62.dfsg.1-3.2lenny4.

For the unstable distribution (sid), these problems have been fixed in version 8.71~dfsg-4.

We recommend that you upgrade your ghostscript packages.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-doc", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-aladdin", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-common", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-esp", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-gpl", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.62.dfsg.1-3.2lenny4", rls:"DEB5"))) {
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

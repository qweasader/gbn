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
  script_oid("1.3.6.1.4.1.25623.1.0.56406");
  script_cve_id("CVE-2006-1062", "CVE-2006-1063", "CVE-2006-1064");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-999)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-999");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-999");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-999");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lurker' package(s) announced via the DSA-999 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in lurker, an archive tool for mailing lists with integrated search engine. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-1062

Lurker's mechanism for specifying configuration files was vulnerable to being overridden. As lurker includes sections of unparsed config files in its output, an attacker could manipulate lurker into reading any file readable by the www-data user.

CVE-2006-1063

It is possible for a remote attacker to create or overwrite files in any writable directory that is named 'mbox'.

CVE-2006-1064

Missing input sanitising allows an attacker to inject arbitrary web script or HTML.

The old stable distribution (woody) does not contain lurker packages.

For the stable distribution (sarge) these problems have been fixed in version 1.2-5sarge1.

For the unstable distribution (sid) these problems have been fixed in version 2.1-1.

We recommend that you upgrade your lurker package.");

  script_tag(name:"affected", value:"'lurker' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"lurker", ver:"1.2-5sarge1", rls:"DEB3.1"))) {
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

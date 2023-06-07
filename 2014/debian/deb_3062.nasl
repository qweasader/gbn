# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.703062");
  script_cve_id("CVE-2014-4877");
  script_tag(name:"creation_date", value:"2014-10-31 23:00:00 +0000 (Fri, 31 Oct 2014)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3062");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3062");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3062");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wget' package(s) announced via the DSA-3062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HD Moore of Rapid7 discovered a symlink attack in Wget, a command-line utility to retrieve files via HTTP, HTTPS, and FTP. The vulnerability allows to create arbitrary files on the user's system when Wget runs in recursive mode against a malicious FTP server. Arbitrary file creation may override content of user's files or permit remote code execution with the user privilege.

This update changes the default setting in Wget such that it no longer creates local symbolic links, but rather traverses them and retrieves the pointed-to file in such a retrieval.

For the stable distribution (wheezy), this problem has been fixed in version 1.13.4-3+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1.16-1.

We recommend that you upgrade your wget packages.");

  script_tag(name:"affected", value:"'wget' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"wget", ver:"1.13.4-3+deb7u2", rls:"DEB7"))) {
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

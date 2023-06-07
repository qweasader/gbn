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
  script_oid("1.3.6.1.4.1.25623.1.0.53722");
  script_cve_id("CVE-2003-0012", "CVE-2003-0013");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-230");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-230");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-230");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bugzilla' package(s) announced via the DSA-230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in Bugzilla, a web-based bug tracking system, by its authors. The Common Vulnerabilities and Exposures Project identifies the following vulnerabilities:

CAN-2003-0012 (BugTraq ID 6502)

The provided data collection script intended to be run as a nightly cron job changes the permissions of the data/mining directory to be world-writable every time it runs. This would enable local users to alter or delete the collected data.

CAN-2003-0013 (BugTraq ID 6501)

The default .htaccess scripts provided by checksetup.pl do not block access to backups of the localconfig file that might be created by editors such as vi or emacs (typically these will have a .swp or ~ suffix). This allows an end user to download one of the backup copies and potentially obtain your database password.

This does not affect the Debian installation because there is no .htaccess as all data file aren't under the CGI path as they are on the standard Bugzilla package. Additionally, the configuration is in /etc/bugzilla/localconfig and hence outside of the web directory.

For the current stable distribution (woody) these problems have been fixed in version 2.14.2-0woody4.

The old stable distribution (potato) does not contain a Bugzilla package.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your bugzilla packages.");

  script_tag(name:"affected", value:"'bugzilla' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bugzilla-doc", ver:"2.14.2-0woody4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bugzilla", ver:"2.14.2-0woody4", rls:"DEB3.0"))) {
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

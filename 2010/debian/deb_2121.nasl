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
  script_oid("1.3.6.1.4.1.25623.1.0.68462");
  script_cve_id("CVE-2010-3714", "CVE-2010-3715", "CVE-2010-3716", "CVE-2010-3717", "CVE-2010-4068");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2121");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2121");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2121");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in TYPO3. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3714

Multiple remote file disclosure vulnerabilities in the jumpUrl mechanism and the Extension Manager allowed attackers to read files with the privileges of the account under which the web server was running.

CVE-2010-3715

The TYPO3 backend contained several cross-site scripting vulnerabilities, and the RemoveXSS function did not filter all Javascript code.

CVE-2010-3716

Malicious editors with user creation permission could escalate their privileges by creating new users in arbitrary groups, due to lack of input validation in the taskcenter.

CVE-2010-3717

TYPO3 exposed a crash bug in the PHP filter_var function, enabling attackers to cause the web server process to crash and thus consume additional system resources.

For the stable distribution (lenny), these problems have been fixed in version 4.2.5-1+lenny6.

For the unstable distribution (sid) and the upcoming stable distribution (squeeze), these problems have been fixed in version 4.3.7-1.

We recommend that you upgrade your TYPO3 packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny6", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny6", rls:"DEB5"))) {
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

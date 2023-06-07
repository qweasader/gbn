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
  script_oid("1.3.6.1.4.1.25623.1.0.66807");
  script_cve_id("CVE-2009-4297", "CVE-2009-4298", "CVE-2009-4299", "CVE-2009-4301", "CVE-2009-4302", "CVE-2009-4303", "CVE-2009-4305");
  script_tag(name:"creation_date", value:"2010-02-10 20:51:26 +0000 (Wed, 10 Feb 2010)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1986)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1986");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1986");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1986");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-1986 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Moodle, an online course management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4297

Multiple cross-site request forgery (CSRF) vulnerabilities have been discovered.

CVE-2009-4298

It has been discovered that the LAMS module is prone to the disclosure of user account information.

CVE-2009-4299

The Glossary module has an insufficient access control mechanism.

CVE-2009-4301

Moodle does not properly check permissions when the MNET service is enabled, which allows remote authenticated servers to execute arbitrary MNET functions.

CVE-2009-4302

The login/index_form.html page links to an HTTP page instead of using an SSL secured connection.

CVE-2009-4303

Moodle stores sensitive data in backup files, which might make it possible for attackers to obtain them.

CVE-2009-4305

It has been discovered that the SCORM module is prone to an SQL injection.

Additionally, an SQL injection in the update_record function, a problem with symbolic links and a verification problem with Glossary, database and forum ratings have been fixed.

For the stable distribution (lenny), these problems have been fixed in version 1.8.2.dfsg-3+lenny3.

For the oldstable distribution (etch), there are no fixed packages available and it is too hard to backport many of the fixes. Therefore, we recommend to upgrade to the lenny version.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 1.8.2.dfsg-6.

We recommend that you upgrade your moodle packages.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.8.2.dfsg-3+lenny3", rls:"DEB5"))) {
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

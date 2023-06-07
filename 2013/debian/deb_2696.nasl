# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.702696");
  script_cve_id("CVE-2013-3551");
  script_tag(name:"creation_date", value:"2013-05-28 22:00:00 +0000 (Tue, 28 May 2013)");
  script_version("2023-04-03T10:19:50+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:50 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 19:34:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-2696)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2696");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2696");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2696");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DSA-2696 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the Open Ticket Request System, which can be exploited by malicious users to disclose potentially sensitive information.

An attacker with a valid agent login could manipulate URLs in the ticket split mechanism to see contents of tickets they are not permitted to see.

The oldstable distribution (squeeze) is not affected by this issue.

For the stable distribution (wheezy), this problem has been fixed in version 3.1.7+dfsg1-8+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 3.2.7-1.

For the unstable distribution (sid), this problem has been fixed in version 3.2.7-1.

We recommend that you upgrade your otrs2 packages.");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"3.1.7+dfsg1-8+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"3.1.7+dfsg1-8+deb7u1", rls:"DEB7"))) {
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

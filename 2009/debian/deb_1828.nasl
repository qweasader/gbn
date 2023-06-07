# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.64380");
  script_cve_id("CVE-2009-0667");
  script_tag(name:"creation_date", value:"2009-07-15 02:21:35 +0000 (Wed, 15 Jul 2009)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1828)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1828");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1828");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1828");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ocsinventory-agent' package(s) announced via the DSA-1828 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ocsinventory-agent which is part of the ocsinventory suite, a hardware and software configuration indexing service, is prone to an insecure perl module search path. As the agent is started via cron and the current directory (/ in this case) is included in the default perl module path the agent scans every directory on the system for its perl modules. This enables an attacker to execute arbitrary code via a crafted ocsinventory-agent perl module placed on the system.

The oldstable distribution (etch) does not contain ocsinventory-agent.

For the stable distribution (lenny), this problem has been fixed in version 1:0.0.9.2repack1-4lenny1.

For the testing distribution (squeeze), this problem has been fixed in version 1:0.0.9.2repack1-5

For the unstable distribution (sid), this problem has been fixed in version 1:0.0.9.2repack1-5.

We recommend that you upgrade your ocsinventory-agent packages.");

  script_tag(name:"affected", value:"'ocsinventory-agent' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ocsinventory-agent", ver:"1:0.0.9.2repack1-4lenny1", rls:"DEB5"))) {
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

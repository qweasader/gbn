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
  script_oid("1.3.6.1.4.1.25623.1.0.67341");
  script_cve_id("CVE-2009-3700", "CVE-2009-3826");
  script_tag(name:"creation_date", value:"2010-05-04 03:52:15 +0000 (Tue, 04 May 2010)");
  script_version("2023-04-03T10:19:49+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:19:49 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2040");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2040");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2040");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squidguard' package(s) announced via the DSA-2040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that in squidguard, a URL redirector/filter/ACL plugin for squid, several problems in src/sgLog.c and src/sgDiv.c allow remote users to either:

cause a denial of service, by requesting long URLs containing many slashes, this forces the daemon into emergency mode, where it does not process requests anymore.

bypass rules by requesting URLs whose length is close to predefined buffer limits, in this case 2048 for squidguard and 4096 or 8192 for squid (depending on its version).

For the stable distribution (lenny), this problem has been fixed in version 1.2.0-8.4+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 1.2.0-9.

We recommend that you upgrade your squidguard package.");

  script_tag(name:"affected", value:"'squidguard' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squidguard", ver:"1.2.0-8.4+lenny1", rls:"DEB5"))) {
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

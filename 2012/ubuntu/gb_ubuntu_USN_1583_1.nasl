# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.841163");
  script_cve_id("CVE-2011-1005", "CVE-2012-2125", "CVE-2012-2126");
  script_tag(name:"creation_date", value:"2012-09-27 03:37:41 +0000 (Thu, 27 Sep 2012)");
  script_version("2022-09-16T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:40 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1583-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1583-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1' package(s) announced via the USN-1583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ruby incorrectly allowed untainted strings to be
modified in protective safe levels. An attacker could use this flaw to bypass
intended access restrictions. (CVE-2011-1005)

John Firebaugh discovered that the RubyGems remote gem fetcher did not properly
verify SSL certificates. A remote attacker could exploit this to perform a man
in the middle attack to alter gem files being downloaded for installation.
(CVE-2012-2126)

John Firebaugh discovered that the RubyGems remote gem fetcher allowed
redirection from HTTPS to HTTP. A remote attacker could exploit this to perform
a machine-in-the-middle attack to alter gem files being downloaded for
installation. (CVE-2012-2125)");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.0-1ubuntu2.2", rls:"UBUNTU12.04 LTS"))) {
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

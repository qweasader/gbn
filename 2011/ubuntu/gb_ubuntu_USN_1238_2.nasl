# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.840784");
  script_tag(name:"creation_date", value:"2011-10-31 12:45:00 +0000 (Mon, 31 Oct 2011)");
  script_version("2022-09-16T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:39 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1238-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1238-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1238-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/881361");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-1238-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1238-1 fixed vulnerabilities in Puppet. The upstream patch introduced a
regression in Ubuntu 11.04 when executing certain commands. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Puppet incorrectly handled the non-default
 'certdnsnames' option when generating certificates. If this setting was
 added to puppet.conf, the puppet primary server's DNS alt names were
 added to the X.509 Subject Alternative Name field of all certificates,
 not just the puppet primary server' certificate. An attacker that has an
 incorrect agent certificate in his possession can use it to impersonate
 the puppet primary server in a machine-in-the-middle attack.");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.4-2ubuntu2.6", rls:"UBUNTU11.04"))) {
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
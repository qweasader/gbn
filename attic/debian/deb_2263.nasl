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
  script_oid("1.3.6.1.4.1.25623.1.0.70694");
  script_tag(name:"creation_date", value:"2012-02-11 08:22:33 +0000 (Sat, 11 Feb 2012)");
  script_version("2023-03-13T10:19:44+0000");
  script_tag(name:"last_modification", value:"2023-03-13 10:19:44 +0000 (Mon, 13 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2263");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2263");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'movabletype-opensource' package(s) announced via the DSA-2263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Movable Type, a weblog publishing system, contains several security vulnerabilities:

A remote attacker could execute arbitrary code in a logged-in users' web browser.

A remote attacker could read or modify the contents in the system under certain circumstances.

For the oldstable distribution (lenny), these problems have been fixed in version 4.2.3-1+lenny3.

For the stable distribution (squeeze), these problems have been fixed in version 4.3.5+dfsg-2+squeeze2.

For the testing distribution (wheezy) and for the unstable distribution (sid), these problems have been fixed in version 4.3.6.1+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages.

This VT has been deprecated as a duplicate of the VT 'Debian Security Advisory DSA 2263-1 (movabletype-opensource)' (OID: 1.3.6.1.4.1.25623.1.0.69969).");

  script_tag(name:"affected", value:"'movabletype-opensource' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
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
  script_oid("1.3.6.1.4.1.25623.1.0.64821");
  script_cve_id("CVE-2009-2946");
  script_tag(name:"creation_date", value:"2009-09-09 00:15:49 +0000 (Wed, 09 Sep 2009)");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1878-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1878-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1878");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'devscripts' package(s) announced via the DSA-1878-1 advisory. [This VT has been merged into the VT 'deb_1878.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64821).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Raphael Geissert discovered that uscan, a program to check for availability of new source code versions which is part of the devscripts package, runs Perl code downloaded from potentially untrusted sources to implement its URL and version mangling functionality. This update addresses this issue by reimplementing the relevant Perl operators without relying on the Perl interpreter, trying to preserve backwards compatibility as much as possible.

For the old stable distribution (etch), this problem has been fixed in version 2.9.26etch4.

For the stable distribution (lenny), this problem has been fixed in version 2.10.35lenny6.

For the unstable distribution (sid), this problem will be fixed in version 2.10.54.

We recommend that you upgrade your devscripts package.");

  script_tag(name:"affected", value:"'devscripts' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
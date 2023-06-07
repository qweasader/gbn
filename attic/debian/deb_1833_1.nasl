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
  script_oid("1.3.6.1.4.1.25623.1.0.64421");
  script_cve_id("CVE-2009-0692");
  script_tag(name:"creation_date", value:"2009-07-29 17:28:37 +0000 (Wed, 29 Jul 2009)");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1833-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1833");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dhcp3' package(s) announced via the DSA-1833-1 advisory. [This VT has been merged into the VT 'deb_1833.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64421).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in ISC's DHCP implementation:

CVE-2009-0692

It was discovered that dhclient does not properly handle overlong subnet mask options, leading to a stack-based buffer overflow and possible arbitrary code execution.

CVE-2009-1892

Christoph Biedl discovered that the DHCP server may terminate when receiving certain well-formed DHCP requests, provided that the server configuration mixes host definitions using 'dhcp-client-identifier' and 'hardware ethernet'. This vulnerability only affects the lenny versions of dhcp3-server and dhcp3-server-ldap.

For the old stable distribution (etch), these problems have been fixed in version 3.0.4-13+etch2.

For the stable distribution (lenny), this problem has been fixed in version 3.1.1-6+lenny2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your dhcp3 packages.");

  script_tag(name:"affected", value:"'dhcp3' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
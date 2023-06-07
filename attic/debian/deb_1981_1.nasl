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
  script_oid("1.3.6.1.4.1.25623.1.0.66774");
  script_cve_id("CVE-2010-0301");
  script_tag(name:"creation_date", value:"2010-02-01 17:25:19 +0000 (Mon, 01 Feb 2010)");
  script_version("2022-07-28T10:10:25+0000");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1981-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1981-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1981");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'maildrop' package(s) announced via the DSA-1981-1 advisory. [This VT has been merged into the VT 'deb_1981.nasl' (OID: 1.3.6.1.4.1.25623.1.0.66774).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christoph Anton Mitterer discovered that maildrop, a mail delivery agent with filtering abilities, is prone to a privilege escalation issue that grants a user root group privileges.

For the oldstable distribution (etch), this problem has been fixed in version 2.0.2-11+etch1.

For the stable distribution (lenny), this problem has been fixed in version 2.0.4-3+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your maildrop packages.");

  script_tag(name:"affected", value:"'maildrop' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
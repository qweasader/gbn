# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.58669");
  script_cve_id("CVE-2007-3917");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1386-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1386");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wesnoth' package(s) announced via the DSA-1386-1 advisory.

This VT has been merged into the VT 'Debian: Security Advisory (DSA-1386)' (OID: 1.3.6.1.4.1.25623.1.0.58668).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A problem has been discovered in the processing of chat messages. Overly long messages are truncated by the server to a fixed length, without paying attention to the multibyte characters. This leads to invalid UTF-8 on clients and causes an uncaught exception. Note that both wesnoth and the wesnoth server are affected.

For the old stable distribution (sarge) this problem has been fixed in version 0.9.0-6 and in version 1.2.7-1~bpo31+1 of sarge-backports.

For the stable distribution (etch) this problem has been fixed in version 1.2-2 and in version 1.2.7-1~bpo40+1 of etch-backports.

For the unstable distribution (sid) this problem has been fixed in version 1.2.7-1.

Packages for the oldstable mips architecture will be added to the archive later.

We recommend that you upgrade your wesnoth packages.");

  script_tag(name:"affected", value:"'wesnoth' package(s) on Debian 4, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
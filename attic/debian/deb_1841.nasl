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
  script_oid("1.3.6.1.4.1.25623.1.0.66803");
  script_cve_id("CVE-2009-2108");
  script_tag(name:"creation_date", value:"2010-02-10 20:51:26 +0000 (Wed, 10 Feb 2010)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1841)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1841");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1841");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git-core' package(s) announced via the DSA-1841 advisory.

  This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-1841-1)' (OID: 1.3.6.1.4.1.25623.1.0.64480).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that git-daemon which is part of git-core, a popular distributed revision control system, is vulnerable to denial of service attacks caused by a programming mistake in handling requests containing extra unrecognized arguments which results in an infinite loop. While this is no problem for the daemon itself as every request will spawn a new git-daemon instance, this still results in a very high CPU consumption and might lead to denial of service conditions.

For the oldstable distribution (etch), this problem has been fixed in version 1.4.4.4-4+etch3.

For the stable distribution (lenny), this problem has been fixed in version 1.5.6.5-3+lenny2.

For the testing distribution (squeeze), this problem has been fixed in version 1:1.6.3.3-1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.6.3.3-1.

We recommend that you upgrade your git-core packages.");

  script_tag(name:"affected", value:"'git-core' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

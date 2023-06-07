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
  script_oid("1.3.6.1.4.1.25623.1.0.69961");
  script_cve_id("CVE-2011-1760");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2022-07-29T10:10:43+0000");
  script_tag(name:"last_modification", value:"2022-07-29 10:10:43 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2254-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2254");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'oprofile' package(s) announced via the DSA-2254-1 advisory. [This VT has been merged into the VT 'deb_2254.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69961).]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OProfile is a performance profiling tool which is configurable by opcontrol, its control utility. Stephane Chauveau reported several ways to inject arbitrary commands in the arguments of this utility. If a local unprivileged user is authorized by sudoers file to run opcontrol as root, this user could use the flaw to escalate his privileges.

For the oldstable distribution (lenny), this problem has been fixed in version 0.9.3-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 0.9.6-1.1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 0.9.6-1.2.

For the unstable distribution (sid), this problem has been fixed in version 0.9.6-1.2.

We recommend that you upgrade your oprofile packages.");

  script_tag(name:"affected", value:"'oprofile' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
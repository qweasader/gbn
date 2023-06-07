# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2011.2203");
  script_tag(name:"creation_date", value:"2023-04-26 04:20:37 +0000 (Wed, 26 Apr 2023)");
  script_version("2023-05-23T11:14:48+0000");
  script_tag(name:"last_modification", value:"2023-05-23 11:14:48 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2203");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2203");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2203");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-2203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Network Security Service libraries marks several fraudulent HTTPS certificates as unstrusted.

For the oldstable distribution (lenny), this problem has been fixed in version 3.12.3.1-0lenny4.

For the stable distribution (squeeze), this problem has been fixed in version 3.12.8-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 3.12.9.with.ckbi.1.82-1.

We recommend that you upgrade your nss packages.

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DSA-2203)' (OID: 1.3.6.1.4.1.25623.1.0.69339).");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 6, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3326");
  script_tag(name:"creation_date", value:"2023-03-21 04:22:51 +0000 (Tue, 21 Mar 2023)");
  script_version("2023-05-23T11:14:48+0000");
  script_tag(name:"last_modification", value:"2023-05-23 11:14:48 +0000 (Tue, 23 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3326)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3326");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3326");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/isc-dhcp");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'isc-dhcp' package(s) announced via the DLA-3326 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Under not completely understood conditions, dhclient completely removes IPv6 addresses from use and is unable to restore them.

For Debian 10 buster, this problem has been fixed in version 4.4.1-2+deb10u3.

We recommend that you upgrade your isc-dhcp packages.

For the detailed security status of isc-dhcp please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DLA-3326)' (OID: 1.3.6.1.4.1.25623.1.0.893326).");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

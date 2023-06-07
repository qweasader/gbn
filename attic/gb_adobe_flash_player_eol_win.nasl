# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.814038");
  script_version("2021-05-06T09:11:05+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-05-06 09:11:05 +0000 (Thu, 06 May 2021)");
  script_tag(name:"creation_date", value:"2018-09-21 12:06:57 +0530 (Fri, 21 Sep 2018)");
  script_name("Adobe Flash Player End of Life (EOL) Detection (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_tag(name:"summary", value:"The Adobe Flash Player on the remote host has reached the End of
  Life (EOL) / is discontinued and should not be used anymore.

  This VT has been replaced by the VT 'Adobe Flash Player End of Life (EOL) Detection' (OID:
  1.3.6.1.4.1.25623.1.0.117197).");

  script_tag(name:"impact", value:"An EOL / discontinued product is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The product has reached its EOL.");

  script_tag(name:"vuldetect", value:"Checks if the target host is using an EOL / discontinued
  product.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
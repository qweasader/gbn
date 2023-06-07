###############################################################################
# OpenVAS Vulnerability Test
#
# Sonicwall GMS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105871");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-11-26T07:23:17+0000");
  script_tag(name:"last_modification", value:"2020-11-26 07:23:17 +0000 (Thu, 26 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-08-16 11:54:25 +0200 (Tue, 16 Aug 2016)");
  script_name("Sonicwall GMS Detection");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'SonicWall Global Management System (GMS) /
  Universal Management Suite (USM) / Analyzer Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.107120).

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

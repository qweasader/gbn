###############################################################################
# OpenVAS Vulnerability Test
#
# Linksys WVBRO-25 Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140624");
  script_version("2020-11-26T07:23:17+0000");
  script_tag(name:"last_modification", value:"2020-11-26 07:23:17 +0000 (Thu, 26 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-12-22 13:08:48 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys WVBRO-25 Detection");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'Linksys Device Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.812041).

  Detection of Linksys WVBRO-25.

The script sends a connection request to the server and attempts to detect Linksys WVBRO-25 and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

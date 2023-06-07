###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ServiceDesk Plus Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103183");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2011-06-29 13:12:41 +0200 (Wed, 29 Jun 2011)");
  script_name("ManageEngine ServiceDesk Plus Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"Detects the installed version of ManageEngine ServiceDesk Plus.

  This script sends an HTTP GET request and tries to get the version from the
  response.

  This VT has been replaced by ManageEngine ServiceDesk Plus Detection (HTTP) (OID: 1.3.6.1.4.1.25623.1.0.140780)");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

exit(66);

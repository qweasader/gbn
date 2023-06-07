# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142073");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-03-06 09:53:10 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo DroboAccess Detection");

  script_tag(name:"summary", value:"Detection of Drobo DroboAccess.

The script sends a connection request to the server and attempts to detect Drobo DroboAccess, a web interface
for Drobo NAS devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8060);

if (!http_can_host_php(port: port))
  exit(0);

# This seems to be the login page which differs from the admin page
res = http_get_cache(port: port, item: "/index.php/login");

if ("Drobo Access" >< res && 'class="infield">Password' >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/port", value: port);
}

# The "admin" page which is normally on another port (8080)
res = http_get_cache(port: port, item: "/DroboAccess/");

if ("title>DroboAccess DroboApp</title>" >< res && "Password strength" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/detected", value: TRUE);
  set_kb_item(name: "drobo/droboaccess/port", value: port);
}

exit(0);

##############################################################################
# OpenVAS Vulnerability Test
#
# HP Diagnostics Server Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802389");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-05-31T20:54:22+0100");
  script_tag(name:"last_modification", value:"2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-02-02 10:43:19 +0530 (Thu, 02 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HP Diagnostics Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2006);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of HP Diagnostics Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:2006);

res = http_get_cache(item:"/", port:port);

if((">HP Diagnostics" >< res && "Hewlett-Packard Development" >< res) ||
   (">HPE Diagnostics" >< res && 'diagName">Diagnostics Server' >< res)) {

  version = "unknown";

  vers = eregmatch(pattern:">Server ([0-9.]+)", string:res);
  if(!vers)
    vers = eregmatch(pattern:'version">Version ([0-9.]+)', string:res);

  if(vers[1])
    version = vers[1];

  set_kb_item(name:"hp/diagnostics_server/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:hp:diagnostics_server:");
  if(!cpe)
    cpe = "cpe:/a:hp:diagnostics_server";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"HP Diagnostics Server", version:vers, install:"/",
                                          cpe:cpe, concluded:vers[0]),
              port:port);
}

exit(0);

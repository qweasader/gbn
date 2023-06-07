###############################################################################
# OpenVAS Vulnerability Test
#
# Cambium Networks cnPilot Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140630");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Cambium Networks cnPilot over HTTP

The script sends a connection request to the server and attempts to detect Cambium Networks cnPilot and to
extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/wifi/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/index.asp");

if ('product_name="cnPilot' >< res) {
  set_kb_item(name: "cambium_cnpilot/detected", value: TRUE);
  set_kb_item(name: "cambium_cnpilot/http/detected", value: TRUE);
  set_kb_item(name: "cambium_cnpilot/http/port", value: port);

  # var product_name="cnPilot R201P";
  mod = eregmatch(pattern: 'product_name="cnPilot ([^"]+)', string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "cambium_cnpilot/http/" + port + "/model", value: mod[1]);

  # 4.3.4-R8(201712131041)&nbsp;
  vers = eregmatch(pattern: "Capture.status_basic.firmware_v.</script></td>.*([0-9].[0-9].[0-9]-R[0-9])",
                   string: res);
  if (isnull(vers[1])) {
    vers = eregmatch(pattern: "Capture.status_basic.firmware_v.</script></td>.*([0-9].[0-9]-R[0-9])",
                     string: res);
  }

  if (!isnull(vers[1])) {
    set_kb_item(name: "cambium_cnpilot/http/" + port + "/fw_version", value: vers[1]);
    set_kb_item(name: "cambium_cnpilot/http/" + port + "/concluded", value: vers[0]);
  }
}

exit(0);

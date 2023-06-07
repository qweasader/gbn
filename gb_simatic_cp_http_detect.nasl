###############################################################################
# OpenVAS Vulnerability Test
#
# Siemens SIMATIC CP Device Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140737");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-01 17:03:54 +0700 (Thu, 01 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC CP Device Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Siemens SIMATIC CP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: '/Portal0000.htm');

if ('Title_Area_Name">CP ' >< res && '"Simatic S7 CP"' >< res) {
  set_kb_item(name: "simatic_cp/detected", value: TRUE);
  set_kb_item(name: "simatic_cp/http/detected", value: TRUE);
  set_kb_item(name: "simatic_cp/http/port", value: port);

  mod = eregmatch(pattern: 'Title_Area_Name">(CP [^<]+)', string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "simatic_cp/http/" + port + "/model", value: mod[1]);

  url = '/Portal1000.htm';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  x = 0;
  lines = split(res);
  foreach line (lines) {
    if ("Firmware:" >< line ) {
      ver = eregmatch(pattern: ">V([^<]+)<", string: lines[x+1]);
      if (!isnull(ver[1])) {
        set_kb_item(name: "simatic_cp/http/" + port + "/version", value: ver[1]);
        replace_kb_item(name: "simatic_cp/http/" + port + "/concluded", value: url);
        break;
      }
    }
    x++;
  }

  x = 0;
  foreach line (lines) {
    if ("Order number" >< line) {
      module = eregmatch(pattern: ">([^<]+)", string: lines[x+1]);
      if (!isnull(module[1])) {
        set_kb_item(name: "simatic_cp/http/" + port + "/module", value: module[1]);
        break;
      }
    }
    x++;
  }

  x = 0;
  foreach line (lines) {
    if ("Hardware:" >< line) {
      hw = eregmatch(pattern: ">([0-9]+)", string: lines[x+1]);
      if (!isnull(hw[1])) {
        set_kb_item(name: "simatic_cp/http/" + port + "/hw_version", value: hw[1]);
        break;
      }
    }
    x++;
  }
}

exit(0);

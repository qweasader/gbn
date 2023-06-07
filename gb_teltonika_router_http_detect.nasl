##############################################################################
# OpenVAS Vulnerability Test
#
# Teltonika Router Detection (HTTP)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141648");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-11-06 11:36:23 +0700 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Teltonika Router Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Teltonika router.

  HTTP based detection of Teltonika router.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://teltonika.lt/products/networking/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/cgi-bin/luci");

if (("luci-static/teltonikaExp/hints.js" >< res || "Teltonika-RUT" >< res) && "Teltonika solutions" >< res) {
  version = "unknown";
  model = "unknown";

  mod = eregmatch(pattern: "Teltonika-(RUT[0-9]{3})", string: res);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "teltonika/router/detected", value: TRUE);

  if (model != "unknown") {
    os_name = "Teltonika " + model + " Router Firmware";
    hw_name = "Teltonika " + model + " Router";
    os_cpe = "cpe:/o:teltonika:" + tolower(model) + "_firmware";
    hw_cpe = "cpe:/h:teltonika:" + tolower(model);
  } else {
    os_name = "Teltonika Unknown Unknown Router Model Firmware";
    hw_name = "Teltonika Unknown Unknown Router Model";
    os_cpe = "cpe:/o:teltonika:router_firmware";
    hw_cpe = "cpe:/h:teltonika:router";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "Teltonika Router Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  register_product(cpe: hw_cpe, location: "/", port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: "/", cpe: os_cpe);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe);

  log_message(port: port, data: report);
  exit(0);
}

exit(0);

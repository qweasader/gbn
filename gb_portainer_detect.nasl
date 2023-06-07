###############################################################################
# OpenVAS Vulnerability Test
#
# Portainer UI Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114015");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-07-31 12:54:42 +0200 (Tue, 31 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Portainer UI Detection");

  script_tag(name:"summary", value:"Detection of Portainer Dashboard/Web UI.

  The script sends a connection request to the server and attempts to detect Portainer Dashboard UI and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://github.com/portainer/portainer");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 9000);
res1 = http_get_cache(port: port, item: "/");

#src="js/app.ad12640a.js">
id = eregmatch(pattern: 'src="(js/app\\.[^.]+\\.js)">', string: res1);

if(isnull(id[1])) {
  #src="main.1ba5d28d7c94b0be5f82.js">
  id = eregmatch(pattern: 'src="(main\\.([^.]+)\\.js)">', string: res1);
}

if(id[1]) {
  url = "/" + id[1];
  res2 = http_get_cache(port: port, item: url);
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  if("Portainer.ResourceControl" >< res2 || "<portainer-tooltip" >< res2 ||
     'angular.module("portainer.app")' >< res2) {
    version = "unknown";
    install = "/";

    res3 = http_get_cache(port: port, item: "/api/status");

    #"Version":"1.16.5"
    vers = eregmatch(pattern: '"Version":"([0-9.]+)"', string: res3);

    if(vers[1]) version = vers[1];

    set_kb_item(name: "portainer/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:portainer:portainer:"); # CPE is not registered yet

    if(!cpe) cpe = 'cpe:/a:portainer:portainer';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Portainer UI", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),port: port);
  }

}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
#
# Octopus Deploy Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140517");
  script_version("2020-09-10T12:00:21+0000");
  script_tag(name:"last_modification", value:"2020-09-10 12:00:21 +0000 (Thu, 10 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-11-21 13:06:44 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Octopus Deploy Detection");

  script_tag(name:"summary", value:"Detection of Octopus Deploy.

  The script sends a connection request to the server and attempts to detect Octopus Deploy and extract its
  version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://octopus.com/");

  exit(0);
}

CPE = "cpe:/a:octopus:octopus_deploy:";

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

install = "/app";
res = http_get_cache(port: port, item: install);

if (">Octopus Deploy</title>" >< res && ("Sorry, could not connect to the Octopus Deploy server" >< res ||
    'src="waiting-for-octopus' >< res || "Server: Octopus Deploy" >< res || 'alt="Octopus Deploy"' >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: 'ETag: "([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "octopus/octopus_deploy/version", value: version);
  }

  set_kb_item(name: "octopus/octopus_deploy/detected", value: TRUE);

  register_and_report_cpe(app: "Octopus Deploy",
                          ver: version,
                          concluded: vers[0],
                          base: CPE,
                          expr: '^([0-9.]+)',
                          insloc: install,
                          regPort: port,
                          conclUrl: install);

  exit(0);
}

exit(0);

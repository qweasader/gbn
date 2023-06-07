###############################################################################
# OpenVAS Vulnerability Test
#
# Bonita BPM Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106009");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-06-16 09:22:17 +0700 (Tue, 16 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_name("Bonita BPM Detection");

  script_tag(name:"summary", value:"Detection of Bonita BPM.

  The script sends a connection request to the server and attempts to detect Bonita BPM.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 8080);

foreach dir( make_list_unique( "/bonita", http_cgi_dirs( port:port ) ) ) {

  rep_dir = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/login.jsp';
  buf = http_get_cache(item: url, port: port);

  if (buf =~ "^HTTP/1\.[01] 200" && buf =~ "Bonita BPM Portal") {
    vers = string("unknown");
    set_kb_item(name: "bonita_bpm/installed", value: TRUE);

    cpe = "cpe:/a:bonitasoft:bonita_bpm";

    register_product(cpe: cpe, location: rep_dir, port: port, service: "www");

    log_message(data: build_detection_report(app:"Bonita BPM", version: vers, install: rep_dir,
                                             cpe: cpe), port: port);
  }
}

exit(0);

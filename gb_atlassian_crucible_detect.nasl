###############################################################################
# OpenVAS Vulnerability Test
#
# Atlassian Crucible Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112229");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-19 14:40:26 +0100 (Mon, 19 Feb 2018)");
  script_name("Atlassian Crucible Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Atlassian Crucible.

The script sends a connection request to the server and attempts to
extract the version number from the reply.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:443);

foreach dir(make_list_unique("/", "/crucible", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/") dir = "";

  res = http_get_cache(port:port, item:dir + "/");
  if( res == NULL )
    continue;

  if(res =~ "^HTTP/1\.[01] 200" && ('display-name="Crucible"' >< res || "<title>Log in to Crucible" >< res)) {

     vers = "unknown";
     version = eregmatch(string:res, pattern:"\(Version:([0-9.]+)");

     if (!isnull(version[1])) {
        vers = chomp(version[1]);
     }

     set_kb_item(name: string("www/", port, "/crucible"), value: string(vers));
     set_kb_item(name:"atlassian/crucible/detected", value:TRUE);

     cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:atlassian:crucible:");

     if(isnull(cpe))
       cpe = 'cpe:/a:atlassian:crucible';

     register_product(cpe:cpe, location:install, port:port, service:"www");

     log_message(data: build_detection_report(app:"Atlassian Crucible", version:vers, install:install, cpe:cpe, concluded: version[0]),
                 port:port);

     exit(0);

  }
}

exit(0);

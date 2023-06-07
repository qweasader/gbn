###############################################################################
# OpenVAS Vulnerability Test
#
# Idera Uptime Infrastructure Monitor Remote Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808239");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-06-27 17:28:12 +0530 (Mon, 27 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Idera Uptime Infrastructure Monitor Remote Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Idera Uptime Infrastructure Monitor.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

ideraPort = http_get_port(default:80);
if(!http_can_host_php(port:ideraPort))
  exit(0);

res = http_get_cache(item:"/index.php", port:ideraPort);

if(res =~ "^HTTP/1\.[01] 200" && '<title>up.time</title>' >< res &&
   ">Username" >< res && ">Password" >< res)
{
  version = "unknown";

  ver = eregmatch(pattern:'>up.time ([0-9.]+)( .build ([0-9.]+))?', string:res);
  if(ver[1]){
    version = ver[1];
  }
  if(ver[3]){
    build = ver[3];
    set_kb_item(name:"Idera/Uptime/Infrastructure/Monitor/build",value:build);
  }
  set_kb_item( name:"Idera/Uptime/Infrastructure/Monitor/Installed", value:TRUE );

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/a:idera:uptime_infrastructure_monitor:");
  if(!cpe )
    cpe = "cpe:/a:idera:uptime_infrastructure_monitor";

  register_product(cpe:cpe, location:"/", port:ideraPort, service:"www");

  log_message(data:build_detection_report( app:"Idera Uptime Infrastructure Monitor",
                                            version:version + ' Build ' + build,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:version + ' Build ' + build),
                                            port:ideraPort);
}
exit(0);

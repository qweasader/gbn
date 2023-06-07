###############################################################################
# OpenVAS Vulnerability Test
#
# appserver.io Application Server Remote Detect
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811267");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-08-02 10:05:20 +0530 (Wed, 02 Aug 2017)");
  script_name("appserver.io Application Server Remote Detect");

  script_tag(name:"summary", value:"Detection of installed version
  of appserver.io application server.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:9080);
if(!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item: "/", port: port);

if("Server: appserver" >< res && res =~ ">&copy;.*>appserver.io<"
    && "<title>Congratulations! appserver.io" >< res) {

  version = "unknown";
  ver = eregmatch(pattern:"appserver/([0-9.-]+) ", string:res);

  if(ver[1]) {
    # nb: sometimes versions comes with '-'
    version = ereg_replace( string:ver[1], pattern: "-", replace: "." );
    set_kb_item(name:"appserver/io/ApplicationServer/ver", value:version);
  }

  set_kb_item(name:"appserver/io/ApplicationServer/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([ 0-9.]+)", base:"cpe:/a:appserver:io:");
  if(!cpe )
    cpe = "cpe:/a:appserver:io:";


  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"appserver.io Application Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}
exit(0);

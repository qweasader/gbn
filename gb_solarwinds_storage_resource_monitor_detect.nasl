###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Storage Resource Monitor Remote Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809426");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-10-03 15:20:26 +0530 (Mon, 03 Oct 2016)");
  script_name("SolarWinds Storage Resource Monitor Remote Version Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  SolarWinds Storage Resource Monitor.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:9000);

host = http_host_name(port:port);

data = "loginState=checkLogin&loginName=admin&password=";

req = http_post_put_req( port:port,
                     url:'/LoginServlet',
                     data:data,
                     accept_header:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                     add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if(buf =~ "^HTTP/1\.[01] 200" && "SolarWinds - Storage Manager" ><  buf)
{
  cookie = eregmatch( pattern:"Set-Cookie: ([0-9a-zA-Z=]+);", string:buf );
  if(!cookie[1]){
    exit(0);
  }

  req = string("GET /LicenseManager.do?actionName=showLicenseManager HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: ", cookie[1], "\r\n",
               "Connection: keep-alive\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);

  vers = eregmatch(pattern:"Storage Manager  ?v([0-9.]+)", string:res);
  if(vers[1]){
    version = vers[1];
  }
  else{
    version ="Unknown";
  }

  set_kb_item(name:"www/" + port + "/Storage_Manager", value:version);
  set_kb_item(name:"storage_manager/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:solarwinds:storage_resource_monitor:");
  if(!cpe)
    cpe= "cpe:/a:solarwinds:storage_resource_monitor";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"SolarWinds Storage Resource Monitor",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}

exit(0);

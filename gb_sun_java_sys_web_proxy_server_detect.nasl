##############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java System Web Proxy Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800864");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_name("Sun Java System Web Proxy Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Java System Web Proxy Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Sun-Java-System-Web-Proxy-Server/banner");
  script_require_ports("Services/www", 8081, 8080);
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(concl = egrep(string:banner, pattern:"Server: Sun-Java-System-Web-Proxy-Server", icase:TRUE)) {

  concl = chomp(concl);
  version = "unknown";
  vers = eregmatch(pattern:"Server: Sun-Java-System-Web-Proxy-Server/([0-9.]+)", string:banner);
  if(vers[1]) {
    version = vers[1];
    concl = vers[0];
  }

  set_kb_item(name:"Sun/JavaWebProxyServ/Ver", value:version);
  set_kb_item(name:"Sun/JavaWebProxyServ/Installed", value:TRUE);
  set_kb_item(name:"Sun/JavaWebProxyServ/Port", value:port);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:sun:java_system_web_proxy_server:");
  if(!cpe)
    cpe = "cpe:/a:sun:java_system_web_proxy_server";

  register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");
  log_message(data:build_detection_report(app:"Sun Java System Web Proxy Server",
                                          version:version,
                                          install:port + "/tcp",
                                          cpe:cpe,
                                          concluded:concl),
                                          port:port);
}

exit(0);

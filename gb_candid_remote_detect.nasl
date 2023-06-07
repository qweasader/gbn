###############################################################################
# OpenVAS Vulnerability Test
#
# CANDID Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807582");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-05-09 16:11:35 +0530 (Mon, 09 May 2016)");
  script_name("CANDID Remote Version Detection");

  script_tag(name:"summary", value:"Check for the presence of CANDID.

  This script sends an HTTP GET request and tries to check for the presence of CANDID
  from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

candidPort = http_get_port(default:80);
if(!http_can_host_php(port:candidPort)) exit(0);

foreach dir(make_list_unique( "/", "/candid", "/candid/htdocs", http_cgi_dirs(port:candidPort))) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  rcvRes = http_get_cache(item:url, port:candidPort);

  if(">CANDID" >< rcvRes && ">sign in" >< rcvRes && ">register" >< rcvRes)
  {
    version = eregmatch(pattern:'> version ([0-9.]+)', string:rcvRes);
    if(version[1]){
      candidVer = version[1];
    } else {
      candidVer = "Unknown";
    }

    set_kb_item(name:"CANDID/Installed", value:TRUE);

    cpe = build_cpe(value:candidVer, exp:"^([0-9.]+)", base:"cpe:/a:nicholas_berry:candid:");
    if(!cpe)
      cpe = "cpe:/a:nicholas_berry:candid";

    register_product(cpe:cpe, location:install, port:candidPort, service:"www");

    log_message(data: build_detection_report(app: "CANDID",
                                             version: candidVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: candidVer),
                                             port: candidPort);
  }
}

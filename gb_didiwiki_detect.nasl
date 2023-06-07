###############################################################################
# OpenVAS Vulnerability Test
#
# DidiWiki Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807527");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-04-12 10:34:57 +0530 (Tue, 12 Apr 2016)");
  script_name("DidiWiki Remote Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of DidiWiki.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

wikiPort = http_get_port(default:8000);

foreach dir (make_list_unique("/", "/didiwiki", "/wiki", http_cgi_dirs(port:wikiPort)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/WikiHome';

  rcvRes = http_get_cache(item:url, port:wikiPort);

  if('<title>WikiHome</title>' >< rcvRes && '>DidiWiki' >< rcvRes)
  {
    version = eregmatch(pattern:'DidiWiki, Version: ([0-9.]+)', string:rcvRes);
    if(version[1]){
      wikiVer = version[1];
    } else {
      wikiVer = "Unknown";
    }

    set_kb_item(name:"DidiWiki/Installed", value:TRUE);

    cpe = build_cpe(value:wikiVer, exp:"^([0-9.]+)", base:"cpe:/a:didiwiki_project:didiwiki:");
    if(!cpe)
      cpe= "cpe:/a:didiwiki_project:didiwiki";

    register_product(cpe:cpe, location:install, port:wikiPort, service:"www");

    log_message(data: build_detection_report(app: "DidiWiki",
                                             version: wikiVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: wikiVer),
                                             port: wikiPort);

  }
}

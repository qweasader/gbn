###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Unified Communications Manager Detection
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805098");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2015-08-31 15:17:33 +0530 (Mon, 31 Aug 2015)");
  script_name("Cisco Unified Communications Manager Webinterface Detection");

  script_tag(name:"summary", value:"Detection of Cisco Unified Communications Manager Webinterface.

  This script sends an HTTP GET request and tries to check the presence of Cisco
  Unified Communications Manager Webinterface from response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

http_port = http_get_port(default:443);

foreach dir (make_list_unique("/", "/cmplatform", "/cucm", "/ccmuser", "/ccmadmin", http_cgi_dirs(port:http_port)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/showHome.do"), port:http_port);

  if(">Cisco Unified" >< rcvRes && 'www.cisco.com' >< rcvRes)
  {
    Ver = "Unknown";

    set_kb_item(name:"Cisco/CUCM/Installed", value:TRUE);

    cpe= "cpe:/a:cisco:unified_communications_manager";

    register_product(cpe:cpe, location:install, port:http_port, service:"www");

    log_message(data: build_detection_report(app: "Cisco Unified Communications Manager",
                                             version: Ver,
                                             install: install,
                                             cpe: cpe,
                                             concluded: Ver),
                                             port:http_port);

    exit( 0 );
  }
}

exit(0);

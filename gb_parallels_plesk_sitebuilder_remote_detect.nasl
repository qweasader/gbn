###############################################################################
# OpenVAS Vulnerability Test
#
# Parallels Plesk Sitebuilder Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812278");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-12-27 12:18:56 +0530 (Wed, 27 Dec 2017)");
  script_name("Parallels Plesk Sitebuilder Remote Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Parallels Plesk Sitebuilder.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2006);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

ppsPort = http_get_port(default:2006);

url = "/Login.aspx";
ppsRes = http_get_cache(item:url, port:ppsPort);

if("Log in to Plesk Sitebuilder" >< ppsRes && ppsRes =~ "Copyright.*Parallels" &&
   ">Interface language" >< ppsRes && ">User name" >< ppsRes)
{
  ppsVer = "Unknown";

  vers = eregmatch(pattern:"Log in to Plesk Sitebuilder ([0-9.]+)" , string:ppsRes);
  if(vers[1]){
    ppsVer = vers[1];
  }

  set_kb_item(name:"Parallels/Plesk/Sitebuilder/Installed", value:TRUE);

  cpe = build_cpe(value:ppsVer, exp:"^([0-9.]+)", base:"cpe:/a:parallels:parallels_plesk_sitebuilder:");
  if(!cpe)
    cpe = "cpe:/a:parallels:parallels_plesk_sitebuilder";

  register_product(cpe:cpe, location:"/", port:ppsPort, service:"www");

  log_message(data: build_detection_report(app: "Parallels Plesk Sitebuilder",
                                           version: ppsVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: ppsVer),
                                           port: ppsPort);
  exit(0);
}
exit(0);

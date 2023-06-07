###############################################################################
# OpenVAS Vulnerability Test
#
# vCloud Usage Meter Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813874");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-08-24 15:45:47 +0530 (Fri, 24 Aug 2018)");
  script_name("vCloud Usage Meter Remote Version Detection");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"summary", value:"Detects the installed version of
  vCloud Usage Meter.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:8443 );

buf = http_get_cache( port:port, item:"/um/" );

if(buf !~ "<title>VMware vCloud Usage Meter.*</title>" ||
   ">User Name" >!< buf || ">Password<" >!< buf){
  exit(0);
}

vers = 'unknown';
set_kb_item( name:"vmware/vcloud/usage/meter/installed", value:TRUE );

version = eregmatch(string: buf, pattern: ">VMware vCloud Usage Meter ([0-9.]+)</span>");
if(version[1]){
  vers = version[1];
}

cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vcloud_usage_meter:");
if(isnull(cpe))
cpe = 'cpe:/a:vmware:vcloud_usage_meter';

register_product(cpe:cpe, location:"/", port:port, service:"www");
log_message(data: build_detection_report(app: "VMware vCloud Usage Meter",
                                         version: vers, install: "/", cpe: cpe,
                                         concluded: vers),
                                         port: port);

exit(0);

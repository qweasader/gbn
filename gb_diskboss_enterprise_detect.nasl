###############################################################################
# OpenVAS Vulnerability Test
#
# DiskBoss Enterprise Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.140094");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-12-06 16:11:25 +0530 (Tue, 06 Dec 2016)");
  script_name("DiskBoss Enterprise Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  DiskBoss Enterprise.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

dbossPort = http_get_port(default:8080);
res = http_get_cache(item:"/login", port:dbossPort);

if(">DiskBoss Enterprise" >< res &&
   ">User Name" >< res && ">Password" >< res)
{

  dbossVer = "unknown";
  install  = "/";

  vers = eregmatch(pattern:">DiskBoss Enterprise v([0-9.]+)", string:res);
  if(vers[1]) dbossVer = vers[1];

  set_kb_item(name:"Disk/Boss/Enterprise/installed", value:TRUE);

  cpe = build_cpe(value:dbossVer, exp:"([0-9.]+)", base:"cpe:/a:dboss:diskboss_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:dboss:diskboss_enterprise";

  register_product(cpe:cpe, location:install, port:dbossPort, service:"www");
  log_message(data:build_detection_report(app:"DiskBoss Enterprise",
                                          version:dbossVer,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers[0]),
                                          port:dbossPort);
}

exit(0);

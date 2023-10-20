# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809060");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("VX Search Enterprise Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of
  VX Search Enterprise.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
res = http_get_cache(item:"/login", port:port);

if(">VX Search Enterprise" >< res &&
   ">User Name" >< res && ">Password" >< res) {

  version = "unknown";
  vxVer = eregmatch(pattern:">VX Search Enterprise v([0-9.]+)", string:res);
  if(vxVer[1])
    version = vxVer[1];

  set_kb_item(name:"VX/Search/Enterprise/installed", value:TRUE);

  cpe = build_cpe(value:vxVer, exp:"([0-9.]+)", base:"cpe:/a:vx:search_enterprise:");
  if(!cpe)
    cpe = "cpe:/a:vx:search_enterprise";

  register_product(cpe:cpe, location:"/", port:port, service:"www");
  log_message(data:build_detection_report(app:"VX Search Enterprise",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:vxVer[0]),
                                          port:port);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808207");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-25 15:47:33 +0530 (Wed, 25 May 2016)");
  script_name("Pentaho Data Integration (PDI) Suite Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Pentaho Data Integration (PDI) Suite.

  This script sends an HTTP GET request and checks for the presence of
  Pentaho Data Integration (PDI) Suite from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

penPort = http_get_port(default:80);

foreach dir(make_list_unique("/", "/pentaho", "/pentaho-di", "/pentaho-solutions", http_cgi_dirs(port:penPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get(item: dir + "/Login", port:penPort);
  rcvRes = http_send_recv( port:penPort, data:sndReq);

  if("<title>Data Integration Server - Login</title>" >< rcvRes &&
     ">User Name" >< rcvRes && ">Password" >< rcvRes &&
     "Pentaho Corporation" >< rcvRes)
  {
    penVer = "Unknown";

    set_kb_item(name:"Pentaho/PDI/Suite/Installed", value:TRUE);

    cpe = "cpe:/a:pentaho:data_integration";

    register_product(cpe:cpe, location:install, port:penPort, service:"www");

    log_message(data: build_detection_report(app:"Pentaho Data Integration (PDI) Suite",
                                             version:penVer ,
                                             install:install,
                                             cpe:cpe,
                                             concluded:penVer),
                                             port:penPort);
  }
}

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803130");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-19 10:33:12 +0530 (Wed, 19 Dec 2012)");
  script_name("OracleBI Discoverer Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of OracleBI Discoverer.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/discoverer" , http_cgi_dirs(port:port)))
{

  install = dir;
  if(dir == "/") dir = "";

  url =  dir + "/viewer";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if(">OracleBI Discoverer" >< res && ">Oracle Technology" >< res)
 {

   set_kb_item(name:"OracleBI Discoverer/installed", value:TRUE);
   ver = eregmatch(string: res, pattern: "Version ([0-9.]+)");
   if(ver[1])
   {
     set_kb_item(name: string("www/", port, "/OracleBIDiscoverer"), value: string(ver[1]," under ",install));
     set_kb_item(name:"OracleBIDiscoverer/installed", value:TRUE);

     cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:oracle:oraclebi_discoverer:");
     if(isnull(cpe))
       cpe = "cpe:/a:oracle:oraclebi_discoverer";

     register_product(cpe:cpe, location:install, port:port, service:"www");
     log_message(data: build_detection_report(app:"OracleBI Discoverer",
                                              version:ver[1],
                                              install:install,
                                              cpe:cpe,
                                              concluded: ver[1]),
                                              port:port);

    }
  }
}

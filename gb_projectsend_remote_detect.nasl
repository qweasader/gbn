# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807549");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-19 11:50:28 +0530 (Tue, 19 Apr 2016)");
  script_name("ProjectSend Remote Version Detection");

  script_tag(name:"summary", value:"Detection of ProjectSend web application.

  This script sends an HTTP GET request and checks for the presence of the
  application.");

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
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

pjtPort = http_get_port(default:80);
if(!http_can_host_php(port:pjtPort))
  exit(0);

foreach dir(make_list_unique( "/", "/ProjectSend",  "/project" , http_cgi_dirs(port:pjtPort))) {

  install = dir;
  if( dir == "/") dir = "";

  url = dir + "/index.php";

  rcvRes = http_get_cache(item:url, port:pjtPort);

  if(rcvRes =~ "Provided by.*>ProjectSend.*Free software" &&
     '<title>Log in' >< rcvRes && '>Username' >< rcvRes &&
     '>Password' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + pjtPort + install, value:version);
    set_kb_item(name:"ProjectSend/Installed", value:TRUE);

    cpe= "cpe:/a:projectsend:projectsend";

    register_product( cpe:cpe, location:install, port:pjtPort, service:"www" );

    log_message(data:build_detection_report(app:"ProjectSend",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:pjtPort);
  }
}

exit(0);

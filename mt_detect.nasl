# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100429");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-06 18:07:55 +0100 (Wed, 06 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Movable Type Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Movable Type.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/mt", "/cgi-bin/mt", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/mt.cgi";
 buf = http_get_cache(item:url, port:port);

 if((egrep(pattern: "<title>Movable Type", string: buf, icase: TRUE) && "Six Apart" >< buf) ||
    "<title>Sign in | Movable Type" >< buf || 'alt="Movable Type"' >< buf) {
    vers = "unknown";
    version = eregmatch(string: buf, pattern: "Version ([0-9.]+)",icase:TRUE);
    if(isnull(version[1]))
      version = eregmatch(pattern:"mt.js\?v=([0-9.]+)", string:buf);

    if (!isnull(version[1]) )
      vers = version[1];

    set_kb_item(name:"movabletype/detected", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:sixapart:movable_type:");
    if(!cpe)
      cpe = 'cpe:/a:sixapart:movable_type';

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data: build_detection_report(app:"Movable Type", version:vers, install:install, cpe:cpe,
                                             concluded: version[0]),
                port:port);
  }
}

exit(0);

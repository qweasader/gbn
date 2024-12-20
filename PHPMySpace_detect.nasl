# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100464");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-01-25 18:49:48 +0100 (Mon, 25 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PHPMySpace Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running PHPMySpace. PHPMySpace is a social networking software
  written in php.");

  script_xref(name:"URL", value:"http://popscript.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

SCRIPT_DESC = "PHPMySpace Detection";

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/register.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: "Powered by phpMySpace Gold", string: buf, icase: TRUE) &&
    egrep(pattern: '<meta name="generator" content="phpMySpace Gold', string: buf)) {

    vers = string("unknown");
    version = eregmatch(string: buf, pattern: "phpMySpace Gold ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
       register_host_detail(name:"App", value:string("cpe:/a:phpmyspace:phpmyspace:",vers,"::gold"), desc:SCRIPT_DESC);
    } else {
       register_host_detail(name:"App", value:string("cpe:/a:phpmyspace:phpmyspace:::gold"), desc:SCRIPT_DESC);
    }

    set_kb_item(name: string("www/", port, "/phpMySpace"), value: string(vers," under ",install));
    set_kb_item(name: "phpmyspace/detected", value: TRUE);

    info = string("phpMySpace Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);

# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16279");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Uebimiau Session Directory Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Uebimiau in default installation create one temporary folder
  to store 'sessions' and other files. This folder is defined  in 'inc/config.php' as './database/'.");

  script_tag(name:"impact", value:"If the web administrator don't change this folder, an attacker
  can exploit this using the follow request:

  http://example.com/database/_sessions/");

  script_tag(name:"solution", value:"1) Insert index.php in each directory of the Uebimiau

  2) Set variable $temporary_directory to a directory not public and with restricted access,
  set permission as read only to 'web server user' for each files in $temporary_directory.

  3) Set open_basedir in httpd.conf to yours clients follow the model below:

  <Directory /server-target/public_html>

    php_admin_value open_basedir

    /server-target/public_html

  </Directory>");

  script_tag(name:"affected", value:"Uebimiau <= 2.7.2 are known to be vulnerable. Other versions might
  be affected as well.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", "/mailpop", "/webmail", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/database/_sessions/";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res)
    continue;

  if(( "Parent Directory" >< res) && ("/database/_sessions" >< res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

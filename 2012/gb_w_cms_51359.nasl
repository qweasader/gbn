# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103384");
  script_version("2023-05-17T09:09:49+0000");
  script_tag(name:"last_modification", value:"2023-05-17 09:09:49 +0000 (Wed, 17 May 2023)");
  script_tag(name:"creation_date", value:"2012-01-11 11:29:25 +0100 (Wed, 11 Jan 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("w-CMS <= 2.0.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"w-CMS is prone to multiple HTML-injection vulnerabilities and a
  local file include (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute
  arbitrary HTML and script code in the context of the affected browser, steal cookie-based
  authentication credentials, and execute arbitrary local scripts in the context of the webserver
  process. Other attacks are also possible.");

  script_tag(name:"affected", value:"w-CMS version 2.0.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51359");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/cms", "/w-cms", "/w_cms", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/" );
  if( ! res || res !~ "^HTTP/1\.[01] 200" || res !~ "Powered by.*w-CMS" )
    continue;

  url = dir + "/?p=<script>alert(/xss-test/)</script>";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/xss-test/\)</script>", check_header:TRUE,
                       extra_check:"Powered by.*w-CMS" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105277");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-12 18:01:07 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Citrix NetScaler Web Management Interface Default Credentials (HTTP) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("citrix/netscaler/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Citrix NetScaler Web Management Interface is using
  known default credentials.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"It was possible to login with default credentials:
  nsroot/nsroot");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

host = http_host_name( port:port );

postdata = "username=nsroot&password=nsroot&timezone_offset=7200";

len = strlen( postdata );
useragent = http_get_user_agent();

req = 'POST /login/do_login HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Referer: http://' + host + '/\r\n' +
      'Cookie: startupapp=neo; is_cisco_platform=0; st_splitter=350px\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len  + '\r\n' +
      '\r\n' +
      postdata;
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "302 Found" >!< buf || "SESSID=" >!< buf )
  exit( 0 );

loc = eregmatch( pattern:'Location: ([^\r\n]+)', string:buf );
if( ! isnull( loc[1] ) )
  url = loc[1];
else
  url = '/menu/neo';

lines = split( buf, keep:FALSE );

foreach line (lines ) {
  if( "SESSID=" >< line )
    co = eregmatch( pattern:'Set-Cookie: SESSID=([a-f0-9]+);', string:line );
}

if( isnull( co[1] ) )
  exit( 0 );

if( http_vuln_check( port:port, url:url, pattern:"Configuration( Utility)?</title>", extra_check:"(neo_logout_url|Welcome nsroot)",  cookie:"startupapp=neo; is_cisco_platform=0; SESSID=" + co[1] ) ) {
  report = 'It was possible to login into the Citrix NetScaler Web Management Interface with username "nsroot" and password "nsroot".';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

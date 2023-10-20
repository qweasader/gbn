# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105412");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Junos Space Web Management Interface Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-19 12:48:28 +0200 (Mon, 19 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_junos_space_webui_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("junos_space_webui/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Junos Space Web Management Interface is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: super/juniper123");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:juniper:junos_space";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/mainui/";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
if( isnull( cookie[1] ) ) exit( 0 );

co = cookie[1];

if( "Junos Space Login</title>" >!< buf || "j_username" >!< buf ) exit( 0 );
useragent = http_get_user_agent();
user = 'super';
pass = 'juniper123';

_ip = eregmatch( pattern:"ipAddr = '([^']+)'", string:buf );
if( ! isnull( _ip[1] ) ) ip = _ip[1];

_code = eregmatch( pattern:"code = '([^']+)'", string:buf );
if( ! isnull( _code[1] ) ) code = _code[1];

if( isnull( ip ) )
  data = 'j_username=' + user;
else
  data = 'j_username=' + user + '%25' + code + '%40' + ip;

data += '&j_screen_username=' + user + '&j_password=' + pass;

len = strlen( data );

host = http_host_name( port:port );

req = 'POST /mainui/j_security_check HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Referer: http://' + host + '/mainui/\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

req = 'GET /mainui/ HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      '\r\n';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "/mainui/?bid=" >!< buf ) exit( 99 );

_bid = eregmatch( pattern:'/mainui/\\?bid=([^\r\n; ]+)', string:buf );

if( isnull( _bid[1] ) ) exit( 0 );

bid = _bid[1];

url = '/mainui/?bid=' + bid;

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      '\r\n';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Junos Space Network Management Platform" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );


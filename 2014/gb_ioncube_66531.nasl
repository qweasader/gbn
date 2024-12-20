# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103932");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("ionCube Loader Wizard 'loader-wizard.php' Multiple Security Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66531");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-04-01 13:11:55 +0200 (Tue, 01 Apr 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"ionCube Loader is prone to the following security vulnerabilities:

  1. A cross-site scripting vulnerability

  2. An information-disclosure vulnerabilities

  3. An Arbitrary File Disclosure Vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"An attacker can exploit these issues to obtain potentially sensitive
  information, to view arbitrary files from the local filesystem and to execute arbitrary script code in
  the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials to launch other attacks.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"ionCube Loader is prone to multiple security vulnerabilities.");

  script_tag(name:"affected", value:"Versions prior to ionCube Loader 2.46 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/ioncube", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/loader-wizard.php?page=phpinfo';

  if( http_vuln_check(port:port, url:url,pattern:"<title>phpinfo()" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

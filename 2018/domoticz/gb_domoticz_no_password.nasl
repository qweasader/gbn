# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113252");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-23 10:40:44 +0200 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Domoticz No Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_domoticz_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("domoticz/detected");

  script_tag(name:"summary", value:"By default, the full control dashboard of Domoticz
  does not require a password.");

  script_tag(name:"vuldetect", value:"Tries to access the control dashboard without a password.");

  script_tag(name:"affected", value:"All Domoticz installations.");

  script_tag(name:"solution", value:"Set a password.");

  exit(0);
}

CPE = "cpe:/a:domoticz:domoticz";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

target_url = location + "/json.htm?type=command&param=getconfig";

buf = http_get_cache( item: target_url, port: port );
if( buf =~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 403" && buf =~ '"DashboardType"' ) {
  report = http_report_vuln_url(  port: port, url: target_url );
  report = 'It was possible to access the control dashboard without a password.\r\n' + report;
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );

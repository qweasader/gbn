# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18375");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-1782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13783");
  script_xref(name:"OSVDB", value:"16871");
  script_xref(name:"OSVDB", value:"16872");
  script_xref(name:"OSVDB", value:"16873");
  script_xref(name:"OSVDB", value:"16874");
  script_xref(name:"OSVDB", value:"16875");
  script_xref(name:"OSVDB", value:"16876");
  script_xref(name:"OSVDB", value:"16877");
  script_xref(name:"OSVDB", value:"16878");
  script_xref(name:"OSVDB", value:"16879");
  script_xref(name:"OSVDB", value:"16880");
  script_xref(name:"OSVDB", value:"16881");
  script_name("BookReview Multiple Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote web server contains a CGI which is vulnerable to multiple cross site
  scripting vulnerabilities.

  Description :

  The remote host is running the BookReview software.

  The remote version of this software is vulnerable to multiple cross-site
  scripting vulnerabilities due to a lack of sanitization of user-supplied data.

  Successful exploitation of this issue may allow an attacker to use the
  remote server to perform an attack against a third-party user.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('XSS'\)</script>", extra_check:"Powered by BookReview", check_header:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

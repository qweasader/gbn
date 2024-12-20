# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19945");
  script_version("2024-01-09T05:06:46+0000");
  script_cve_id("CVE-2005-3152");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CubeCart < 3.0.4 Multiple XSS Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2005/09/cubecart-303-multiple-variable-cross.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14962");

  script_tag(name:"summary", value:"CubeCart is prone to multiple cross-site scripting (XSS)
  vulnerabilities due to its failure to properly sanitize user-supplied input of certain variables
  to the 'index.php' and 'cart.php' scripts.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

if( ! dir = infos["location"] )
  dir = "/";

if( ! safe_checks() ) {

  if( dir == "/" )
    dir = "";

  vtstrings = get_vt_strings();
  xss = "<script>alert('" + vtstrings["lowercase_rand"] + "');</script>";
  exss = urlencode( str:xss );

  url = string( dir, "/upload/index.php?", 'searchStr=">', exss, "&act=viewCat&Submit=Go" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && xss >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ver = infos["version"];
if( ! ver )
  exit( 0 );

if( version_is_less_equal( version:ver, test_version:"3.0.3" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.4", install_url:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

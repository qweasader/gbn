# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:teampass:teampass";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805001");
  script_version("2023-03-24T10:19:42+0000");
  script_cve_id("CVE-2014-3771", "CVE-2014-3772", "CVE-2014-3773", "CVE-2014-3774");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-10-16 16:50:50 +0530 (Thu, 16 Oct 2014)");

  script_name("TeamPass < 2.1.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("teampass/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67473");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/05/19/5");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/05/18/2");

  script_tag(name:"summary", value:"TeamPass is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An Input passed via the 'language' GET parameter to index.php is not properly verified before
  being used to include files.

  - An error within the authentication mechanism can be exploited to access to otherwise restricted
  scripts and subsequently e.g. execute arbitrary PHP code by uploading a malicious PHP script.

  - Input passed via the 'login' POST parameter to sources/main.queries.php (when 'type' is set to
  'send_pw_by_email' or 'generate_new_password') is not properly sanitised before being used in SQL
  queries.

  - Certain input passed to datatable.logs.php and to multiple scripts in sources/datatable/ is not
  properly sanitised before being used in SQL queries.

  - Input passed via the 'group' and 'id' GET parameters to items.php (when both are set) is not
  properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site and manipulate
  SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"TeamPass version 2.1.19 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.20 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

req = http_get( item:dir + "/index.php", port:port );
res = http_keepalive_send_recv( port:port, data:req );

cookie = eregmatch( pattern:"Set-Cookie: (PHPSESSID=[A-Za-z0-9;]+)", string:res );
if( ! isnull( cookie[1] ) )
  cookie = cookie[1];

keycookie = eregmatch( pattern:"(KEY_PHPSESSID=[A-Za-z0-9;%]+)", string:res );
if( ! isnull( keycookie[1] ) )
  cookie = cookie + " " + keycookie[1];

if( isnull( cookie ) )
  exit( 0 );

url = dir + "/sources/upload/upload.files.php?PHPSESSID=";

if( http_vuln_check( port:port, url:url,
                     pattern:"jsonrpc", check_header:TRUE, extra_check:"result",
                     cookie:cookie, check_nomatch:"Hacking attempt\.\.\." ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

